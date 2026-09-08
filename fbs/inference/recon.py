import time
import difflib
import requests
from urllib.parse import urljoin

from fbs.inference.sql_dialects import ERROR_SIGNATURES, detect_db_from_error

BASELINE = 'john35912'

# 언어/공통별 노출 파일 탐지 경로
_EXPOSED_PATHS: dict[str, list[str]] = {
    'base': [
        '.env', '.git/config', '.htaccess',
        'admin/', 'api-docs', 'swagger.json',
    ],
    'PHP':     ['phpinfo.php', 'info.php', 'composer.json', 'composer.lock', 'config.php'],
    'Node.js': ['package.json'],
    'Python':  ['requirements.txt'],
    'Java':    ['actuator/health', 'swagger-ui.html'],
}

# 존재 확인용 breaking 페이로드 — 따옴표 문맥마다 하나씩만 사용한다.
# 주석 우회(-- , #)·bool 매트릭스·시간 기반 등으로 실제 공격 가능 여부를
# 확정하는 건 recon의 역할이 아니라 strategy 단계에서 수행한다.
DB_PROBES_BY_QUOTE: dict[str, str] = {
    "'": "'",
    '"': '"',
}

_WAF_BODY_SIGNATURES = frozenset([
    'hack', 'blocked', 'attack', 'detected', 'illegal',
    'not allowed', 'bad request', 'security violation', 'waf', 'firewall',
])

# 토큰 하나하나를 특정 vuln-type에 매핑해두는 참조 테이블. DBDetect._probe_filter_map()의
# 1단계(종합 카나리, 전체 토큰을 이어붙여서 "필터가 존재하는지"만 vuln-type 무관하게 1번에
# 확인)와 2단계(반응이 있을 때만, 토큰마다 따로 보내서 정확히 뭐가 막히는지 지도를 만듦) 양쪽
# 다 이 딕셔너리의 키(토큰 목록)를 그대로 쓴다. profiler.py가 2단계 결과를 hints 점수로 바꿀 때
# 이 가중치를 쓰는데, 토큰 하나는 자기한테 매핑된 vuln-type에만 점수를 주고 다른 유형엔 절대
# 안 번진다 — 예를 들어 따옴표가 막혔다고 xss 점수가 오르면 안 되니까. 특정 CTF/타겟의 실제
# 필터 목록을 그대로 베끼지 않고, 취약점 유형별 대표 토큰으로 일반화해뒀다.
_FILTER_PROBE_TOKENS: dict[str, dict[str, float]] = {
    # SQLi
    "'":           {'sqli': 0.5},
    '"':           {'sqli': 0.4},
    '--':          {'sqli': 0.4},
    '#':           {'sqli': 0.3},
    '/*':          {'sqli': 0.3},
    'union':       {'sqli': 0.5},
    'select':      {'sqli': 0.5},
    'sleep':       {'sqli': 0.3},
    # XSS
    '<':           {'xss': 0.5},
    '>':           {'xss': 0.3},
    'script':      {'xss': 0.5},
    'onerror':     {'xss': 0.5},
    'javascript:': {'xss': 0.4},
    # SSTI
    '{{':          {'ssti': 0.5},
    '}}':          {'ssti': 0.3},
    '__class__':   {'ssti': 0.5},
    # Path traversal
    '../':         {'path_traversal': 0.5},
    '..\\':        {'path_traversal': 0.4},
    # NoSQLi
    '$where':      {'nosqli': 0.5},
    '$ne':         {'nosqli': 0.4},
    # Command injection
    ';':           {'command_injection': 0.3},
    '|':           {'command_injection': 0.3},
    '`':           {'command_injection': 0.4},
}

# 길이 유사 판정 임계값 (절댓값, 텍스트 유사도 계산 전 빠른 필터)
_LENGTH_THRESHOLD = 100
# 텍스트 유사도 임계값 (SequenceMatcher.ratio 기준)
_SIMILAR_RATIO = 0.85


class DBDetect:
    """
    [Case A] default > baseline: 필드가 쿼리를 필터링하는 상황
      - 에러 프로브 길이 ≈ default → 텍스트 유사도 계산 → SQLi 신호
    [Case B] baseline > default: 이상 상황
      - baseline에서 새로 생긴 텍스트 추출 (오류/리다이렉트 등 의심)

    따옴표 문맥(', ")당 breaking 페이로드 1개로 DB 관여 가능성만 가볍게 확인한다.
    boolean 매트릭스·주석 우회·시간 기반 등 실제 공격 가능 여부 확정은 strategy 몫이다.
    """

    TIMEOUT = 10

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def run(self, url: str, method: str, data: dict, target: str,
            baseline_length: int | None = None,
            baseline_body:   str | None = None,
            baseline_status: int | None = None,
            default_length:  int | None = None,
            default_body:    str | None = None) -> dict:
        """
        필드가 DB 쿼리에 관여하는지 가볍게(따옴표 문맥당 breaking 페이로드 1개) 확인한다.
        주석 우회·boolean 매트릭스·시간 기반 등으로 실제 공격 가능 여부를 확정하는 건
        recon의 역할이 아니라 strategy 단계에서 수행한다.

        반환값: {
            'case':             'A' | 'B' | 'C' | None,
            'baseline_anomaly': str | None,   # Case B일 때 baseline에서 새로 생긴 텍스트
            'db_hint':          str,          # 사람이 읽을 확인 상태 메시지
            'quote_char':       "'" | '"' | None,  # 신호를 낸 따옴표 문맥 (없으면 None)
            'error': {
                payload: {
                    status, status_changed, status_signal,
                    length, length_delta,
                    probe_like_default: bool,
                    default_similarity: float|None,
                    error_snippet: str|None,
                    elapsed, db_type, send_error,
                }
            },
            'sqli_signal': bool,   # 신호일 뿐, 취약점 확정은 strategy에서 수행
            'waf_blocked': bool,
        }
        """
        # ── 전처리: default vs baseline 비교 ─────────────────────────────────
        case = None
        baseline_anomaly = None

        if default_length is not None and baseline_length is not None:
            if abs(default_length - baseline_length) <= _LENGTH_THRESHOLD:
                # Case C: 필드가 쿼리에 무관 — probe≈default 체크 무의미
                case = 'C'
            elif default_length > baseline_length:
                # Case A: 필드가 쿼리를 필터링 중 — 정상적인 SQLi 탐지 대상
                case = 'A'
            else:
                # Case B: baseline이 더 큼 — 이상 상황, 새로 생긴 텍스트 추출
                case = 'B'
                if default_body is not None and baseline_body is not None:
                    baseline_anomaly = self._diff_snippet(default_body, baseline_body)

        # ── 존재 확인: 따옴표 문맥당 breaking 페이로드 1개 ────────────────────
        error_results   = {}
        detected_db     = None
        sqli_signal     = False
        waf_blocked     = False
        triggering_quote = None   # 신호를 낸 따옴표('/") — strategy가 페이로드 구성에 재사용
        # 아래 루프에서 '/"별로 개별 차단 여부를 기록해뒀다가 _probe_filter_map에 넘긴다 —
        # _FILTER_PROBE_TOKENS에도 '/"가 들어있어서, 넘기지 않으면 같은 문자를 또 raw로
        # 보내 중복 확인하게 된다.
        quote_probe_blocked: dict[str, bool] = {}

        for quote_char, payload in DB_PROBES_BY_QUOTE.items():
            probe_data = {**data, target: payload}
            resp, elapsed, send_error = self._send(url, method, probe_data)
            # 주의: requests.Response는 __bool__이 self.ok(2xx/3xx)로 정의돼 있어서
            # "if resp:"는 500 같은 에러 응답도 False로 취급해버린다 — 반드시 is not None으로 비교
            body   = resp.text if resp is not None else ''
            length = len(body)  if resp is not None else None

            length_delta = (
                length - baseline_length
                if length is not None and baseline_length is not None else None
            )

            db_type = detect_db_from_error(body)

            # 상태 코드 변화 감지
            probe_status   = resp.status_code if resp is not None else None
            status_changed = (
                probe_status is not None and baseline_status is not None
                and probe_status != baseline_status
            )
            status_signal  = self._classify_status(probe_status, baseline_status) if status_changed else None
            if status_signal in ('query_error', 'waf'):
                sqli_signal = True
                if triggering_quote is None:
                    triggering_quote = quote_char

            # 요청 자체가 실패 — baseline은 응답을 받았는데 이 페이로드에서만
            # 예외(타임아웃/연결 끊김 등)가 나면 서버에 실제 영향을 준 신호로 취급
            if resp is None and baseline_status is not None:
                status_signal = 'conn_error'
                sqli_signal   = True
                if triggering_quote is None:
                    triggering_quote = quote_char

            # Case A만: probe 길이 ≈ default → 텍스트 유사도 계산
            # Case C는 default ≈ baseline이므로 probe≈default 체크가 무의미해 건너뜀
            probe_like_default = False
            default_similarity = None
            if case == 'A' and length is not None and default_length is not None:
                if abs(length - default_length) <= _LENGTH_THRESHOLD:
                    ratio = difflib.SequenceMatcher(
                        None, body, default_body, autojunk=False
                    ).ratio()
                    default_similarity = round(ratio, 3)
                    if ratio >= _SIMILAR_RATIO:
                        probe_like_default = True
                        sqli_signal = True
                        if triggering_quote is None:
                            triggering_quote = quote_char

            # WAF 차단 — baseline과 다른 길이 + 차단 키워드
            blocked_this_quote = (
                length is not None and baseline_length is not None
                and length != baseline_length and self._detect_waf_body(body)
            )
            if blocked_this_quote:
                waf_blocked = True
            quote_probe_blocked[quote_char] = blocked_this_quote

            error_results[payload] = {
                'status':             probe_status,
                'status_changed':     status_changed,
                'status_signal':      status_signal,
                'length':             length,
                'length_delta':       length_delta,
                'probe_like_default': probe_like_default,
                'default_similarity': default_similarity,
                'error_snippet':      self._extract_snippet(body) if db_type else None,
                'elapsed':            round(elapsed, 3),
                'db_type':            db_type,
                'send_error':         send_error,
            }
            if db_type and not detected_db:
                detected_db = db_type
                if triggering_quote is None:
                    triggering_quote = quote_char

        if waf_blocked:
            sqli_signal = False
            # WAF 차단은 실제 쿼리 반응이 아니라 방화벽 개입이므로 따옴표 신호로 보지 않는다
            triggering_quote = None

        if detected_db:
            db_hint = '에러 시그니처 확인 (DB 존재)'   # 에러 시그니처로 DB 존재를 직접 확인
        elif sqli_signal:
            db_hint = '반응이 다름 (재검증 필요)'     # 반응은 다르지만 확정 근거는 아님 — strategy에서 재검증 필요
        else:
            db_hint = '반응이 없음 (파라미터화, WAF 차단, DB 없음 등)'     # 무반응 — 파라미터화 등으로 안전하거나, WAF 차단이거나, 정말 무관

        # 위 waf_blocked는 '/"만으로 판단해서 SQLi 편향이다 — XSS/SSTI 등 다른 유형만 막는
        # 필터는 따옴표에 반응 안 해서 여기선 안 잡힌다. filter_map은 그것과 별개로, vuln-type
        # 무관한 종합 카나리로 "필터가 존재하는지"부터 확인하고 반응이 있을 때만 토큰별로
        # 개별 확인한다 — SQLi 신호가 없어도(quote가 안 막혀도) 독립적으로 실행된다.
        filter_map = self._probe_filter_map(url, method, data, target, baseline_length, quote_probe_blocked)

        return {
            'case':             case,
            'baseline_anomaly': baseline_anomaly,
            'db_hint':          db_hint,
            'quote_char':       triggering_quote,
            'error':            error_results,
            'sqli_signal':      sqli_signal,
            'waf_blocked':      waf_blocked,
            'filter_map':       filter_map,
            # detect_db_from_error()로 이미 확인된 DB 엔진 이름(SQL_DIALECTS의 키와 동일한
            # 표기: SQLite/MySQL/PostgreSQL/MSSQL/Oracle) — 지금까진 db_hint 문구를 만드는
            # 데만 쓰고 버렸는데, sqli.py가 재탐지 없이 그대로 재사용할 수 있게 노출한다.
            'detected_db':      detected_db,
        }

    def _probe_filter_map(self, url: str, method: str, data: dict, target: str,
                           baseline_length: int | None,
                           known_blocked: dict[str, bool] | None = None) -> dict[str, bool] | None:
        """1단계: 전체 토큰을 이어붙인 종합 카나리 1개로 "필터가 존재하는지"만 vuln-type
        무관하게 확인한다(요청 1개). 반응이 없으면 이 필드엔 어떤 필터도 없다고 보고 추가
        요청 없이 끝낸다(None 반환). 반응이 있으면 2단계로 토큰을 하나씩 개별 요청으로 보내서
        정확히 뭐가 막히는지 지도를 만든다 — 한 요청에 여러 토큰을 같이 보내면 어느 토큰
        때문에 막혔는지 구분이 안 되므로, 2단계는 반드시 토큰 하나당 요청 하나여야 한다.

        known_blocked(위 quote-probe 루프가 '/"에 대해 이미 확인해둔 결과)에 들어있는
        토큰은 2단계에서 또 raw로 보내지 않고 그 결과를 그대로 재사용한다 — _FILTER_PROBE_TOKENS
        에도 '/"가 들어있어서, 안 그러면 완전히 같은 문자를 두 코드 경로가 각자 중복 확인한다."""

        def _reacted(body: str) -> bool:
            length = len(body)
            if baseline_length is not None and abs(length - baseline_length) > _LENGTH_THRESHOLD:
                return True
            return self._detect_waf_body(body)

        known_blocked = known_blocked or {}

        composite = BASELINE + ''.join(_FILTER_PROBE_TOKENS.keys())
        resp, _, _ = self._send(url, method, {**data, target: composite})
        if resp is None or not _reacted(resp.text):
            return None  # 필터 없음 확정 (또는 요청 실패) — 토큰별 breakdown 스킵

        blocked: dict[str, bool] = {}
        for token in _FILTER_PROBE_TOKENS:
            if token in known_blocked:
                blocked[token] = known_blocked[token]
                continue
            t_resp, _, _ = self._send(url, method, {**data, target: BASELINE + token})
            blocked[token] = t_resp is not None and _reacted(t_resp.text)
        return blocked

    def _send(self, url: str, method: str, data: dict) -> tuple[requests.Response | None, float, str | None]:
        start = time.monotonic()
        try:
            if method == 'GET':
                resp = self.session.get(url, params=data, timeout=self.TIMEOUT)
            else:
                resp = self.session.request(method, url, data=data, timeout=self.TIMEOUT)
            return resp, time.monotonic() - start, None
        except Exception as e:
            # 예외를 삼키지 않고 유형을 남긴다 — 타임아웃/연결 끊김도 그 자체로 신호일 수 있음
            return None, time.monotonic() - start, f'{type(e).__name__}: {e}'

    @staticmethod
    def _detect_waf_body(body: str) -> bool:
        lower = body.lower()
        return any(sig in lower for sig in _WAF_BODY_SIGNATURES)

    @staticmethod
    def _classify_status(probe: int | None, baseline: int | None) -> str | None:
        """상태 코드 변화를 분류한다."""
        if probe is None or baseline is None or probe == baseline:
            return None
        if probe == 500:
            return 'query_error'   # 쿼리 구문 깨짐 → SQLi 강신호
        if probe == 403:
            return 'waf'           # WAF 차단
        if probe in (301, 302, 307, 308):
            return 'redirect'      # 리다이렉트 (인증 우회 가능성)
        return 'status_change'     # 기타 상태 코드 변화

    @staticmethod
    def _extract_snippet(body: str, context: int = 200) -> str | None:
        """에러 시그니처 주변 텍스트를 추출한다."""
        lower = body.lower()
        for sigs in ERROR_SIGNATURES.values():
            for sig in sigs:
                idx = lower.find(sig)
                if idx != -1:
                    start = max(0, idx - 50)
                    end   = min(len(body), idx + context)
                    return body[start:end].strip()
        return None

    @staticmethod
    def _diff_snippet(base: str, target: str, max_len: int = 300) -> str | None:
        """target에서 base 대비 새로 추가된 텍스트를 추출한다."""
        matcher = difflib.SequenceMatcher(None, base, target, autojunk=False)
        added = []
        for tag, *_, j1, j2 in matcher.get_opcodes():
            if tag in ('insert', 'replace'):
                added.append(target[j1:j2])
        combined = ''.join(added).strip()
        return combined[:max_len] if combined else None


class Recon:
    TIMEOUT = 10

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def run(self, pages: list[dict]) -> list[dict]:
        """각 페이지의 모든 필드에 baseline 값을 전송하고 응답을 page['recon']에 저장한다."""
        print(f"\n# [리콘] {len(pages)}개 페이지 프로브 시작")
        for page in pages:
            page['recon'] = self._probe_page(page)

        self._annotate_block_ratio(pages)

        for page in pages:
            print(f"  URL: {page['url']}")
            default = page['recon'].get('__default__', {})
            print(f"  [기본] status={default.get('status')} length={default.get('length')}")
            cache = page['recon'].get('__cache__')
            if cache:
                confirmed = '304 확인' if cache['cache_confirmed'] else f"조건부→{cache['conditional_status']}"
                etag_info = f" | etag={cache['etag_type']}({cache['etag']!r})" if cache['etag'] else ''
                lm_info   = f" | last-modified={cache['last_modified']!r}" if cache['last_modified'] else ''
                cdn_info  = f" | CDN={list(cache['cdn_headers'].keys())}" if cache['cdn_headers'] else ''
                print(f"  [캐시] {confirmed}{etag_info}{lm_info}{cdn_info}")
                # weak ETag → Express/Node.js 힌트, framework 미설정 시 보정
                if cache.get('etag_type') == 'weak':
                    ts = page.setdefault('tech_stack', {})
                    if not ts.get('framework'):
                        ts['framework'] = 'Express'
                        print(f"  [tech_stack] ETag weak 포맷 → framework=Express 추가")
            for entry in (page['recon'].get('__exposed__') or []):
                flag = '★' if entry['status'] == 200 else '△'
                note = '접근 차단' if entry['status'] == 403 else f"{entry['length']} bytes"
                print(f"  {flag} [노출 파일] {entry['path']} → {entry['status']} ({note})")
            for field, data in page['recon'].items():
                if field in ('__default__', '__cache__', '__exposed__', '__block_ratio__'):
                    continue
                print(f"  [{field}] baseline: status={data['status']} length={data['length']} elapsed={data['elapsed']}s")
                db = data.get('db', {})
                case = db.get('case')
                if case:
                    print(f"    case={case}", end='')
                    if case == 'B' and db.get('baseline_anomaly'):
                        print(f" | anomaly={db['baseline_anomaly']!r}", end='')
                    print()
                print(f"    db_hint={db.get('db_hint')}")
                if db.get('waf_blocked'):
                    print(f"    ⚠ WAF 차단 의심 — baseline과 다른 길이 + 차단 키워드 감지")
                elif db.get('sqli_signal'):
                    print(f"    ★ SQLi 신호: probe가 default 페이지와 유사")
                filter_map = db.get('filter_map')
                if filter_map:
                    blocked_tokens = [t for t, b in filter_map.items() if b]
                    print(f"    필터 지도 : {len(blocked_tokens)}/{len(filter_map)}개 토큰 차단 — {blocked_tokens}")
                for payload, result in (db.get('error') or {}).items():
                    if result.get('probe_like_default'):
                        db_type = '탐지 가능성 높음'
                    else:
                        db_type = result['db_type'] or '미탐지'
                    snippet  = f" | snippet={result['error_snippet']!r}" if result.get('error_snippet') else ''
                    delta    = f" delta={result['length_delta']:+d}" if result['length_delta'] is not None else ''
                    sim      = f" sim={result['default_similarity']}" if result['default_similarity'] is not None else ''
                    st_sig   = f" ★{result['status_signal'].upper()}" if result.get('status_signal') else ''
                    st_chg   = f"→{result['status']}" if result.get('status_changed') else f"{result['status']}"
                    err      = f" | 요청 실패: {result['send_error']}" if result.get('send_error') else ''
                    print(f"    error probe={payload!r:12s} status={st_chg}{st_sig} length={result['length']}{delta}{sim} db={db_type}{snippet}{err}")
        return pages

    @staticmethod
    def _annotate_block_ratio(pages: list[dict]) -> None:
        """필터 차단이 사이트 전역에 균일하게 걸리는지(범용 인프라 WAF 추정, 신호 약함) 아니면
        일부 필드에만 선택적으로 걸리는지(개발자가 그 필드를 SQL 관련으로 인지하고 일부러
        막았다는 신호, 강함) 판단한다. 페이지 하나만 보면 안 된다 — 예를 들어 id/pw만 있는
        로그인 페이지는 그 안에서 둘 다 막혀도 비교 대상이 없어 균일처럼 보이지만, 사이트
        전체로 보면 다른 무관한 필드(검색창 등)는 안 막히는 선택적 차단일 수 있다."""
        total = blocked = 0
        for page in pages:
            for field, data in page['recon'].items():
                if field in ('__default__', '__cache__', '__exposed__', '__block_ratio__'):
                    continue
                total += 1
                if (data.get('db') or {}).get('waf_blocked'):
                    blocked += 1
        ratio = (blocked / total) if total else 0.0
        for page in pages:
            page['recon']['__block_ratio__'] = ratio
        if total:
            verdict = '균일 차단(범용 WAF 추정, 신호 약함)' if ratio >= 0.5 else '선택적 차단(타겟 필터 추정, 신호 강함)'
            print(f"\n# [리콘] 전역 필터 차단 비율: {blocked}/{total} ({ratio:.0%}) — {verdict}")

    def _probe_page(self, page: dict) -> dict:
        results = {}
        db_detect = DBDetect(self.session)
        base_url = page['url'].split('?')[0]

        # engine.py가 WafDetector보다 먼저 페이지당 baseline GET을 한 번 해두고
        # page['_baseline']에 실어둔다 — 여기서 또 같은 요청을 새로 안 보내고 재사용한다.
        # (없으면, 예를 들어 recon을 단독으로 쓰는 경우엔 그냥 직접 가져온다.)
        baseline = page.get('_baseline')
        if baseline is not None:
            results['__default__'] = {
                'status':  baseline.get('status'),
                'length':  len(baseline['body']) if baseline.get('body') is not None else None,
                'body':    baseline.get('body'),
                'elapsed': baseline.get('elapsed'),
            }
            default_headers = baseline.get('headers') or {}
        else:
            default_resp, default_elapsed = self._send(base_url, 'GET', {})
            results['__default__'] = self._record(default_resp, default_elapsed)
            default_headers = default_resp.headers if default_resp is not None else {}
        default_length = results['__default__']['length']
        default_body   = results['__default__']['body']

        results['__cache__']   = self._probe_cache(base_url, default_headers)
        results['__exposed__'] = self._probe_exposed(base_url, page.get('tech_stack') or {})

        for param in (page.get('params') or {}):
            resp, elapsed = self._send(base_url, 'GET', {param: BASELINE})
            results[param] = self._record(resp, elapsed)
            results[param]['db'] = db_detect.run(
                base_url, 'GET', {param: BASELINE}, param,
                baseline_length=results[param]['length'],
                baseline_body=results[param]['body'],
                baseline_status=results[param]['status'],
                default_length=default_length,
                default_body=default_body,
            )

        for form in (page.get('forms') or []):
            action = form.get('action') or page['url']
            method = form.get('method', 'GET').upper()
            all_inputs = {
                inp['name']: inp.get('value') or BASELINE
                for inp in form.get('inputs', [])
                if inp.get('name')
            }
            for inp in form.get('inputs', []):
                name = inp.get('name')
                if not name:
                    continue
                if inp.get('type') in ('submit', 'button', 'image', 'reset'):
                    continue
                data = {**all_inputs, name: BASELINE}
                resp, elapsed = self._send(action, method, data)
                results[name] = self._record(resp, elapsed)
                results[name]['db'] = db_detect.run(
                    action, method, all_inputs, name,
                    baseline_length=results[name]['length'],
                    baseline_body=results[name]['body'],
                    baseline_status=results[name]['status'],
                    default_length=default_length,
                    default_body=default_body,
                )

        # scanner.py가 퍼징으로 찾은 히든 파라미터(HTML엔 없어서 위 params/forms 루프가
        # 못 본 것들)도 똑같이 DB 관여 여부를 확인한다 — 안 그러면 존재는 확정했는데
        # SQLi 신호 자체는 한 번도 안 찔러본 상태로 profiler에 넘어가게 된다.
        for param in (page.get('hidden_params') or []):
            if param in results:
                continue
            resp, elapsed = self._send(base_url, 'GET', {param: BASELINE})
            results[param] = self._record(resp, elapsed)
            results[param]['db'] = db_detect.run(
                base_url, 'GET', {param: BASELINE}, param,
                baseline_length=results[param]['length'],
                baseline_body=results[param]['body'],
                baseline_status=results[param]['status'],
                default_length=default_length,
                default_body=default_body,
            )

        for entry in (page.get('hidden_post_params') or []):
            name = entry.get('param')
            if not name or name in results:
                continue
            action       = entry.get('action') or page['url']
            known_fields = entry.get('known_fields') or {}
            data = {**known_fields, name: BASELINE}
            resp, elapsed = self._send(action, 'POST', data)
            results[name] = self._record(resp, elapsed)
            results[name]['db'] = db_detect.run(
                action, 'POST', known_fields, name,
                baseline_length=results[name]['length'],
                baseline_body=results[name]['body'],
                baseline_status=results[name]['status'],
                default_length=default_length,
                default_body=default_body,
            )

        return results

    def _probe_cache(self, url: str, headers) -> dict | None:
        """ETag / Last-Modified 헤더가 있으면 조건부 GET을 쏴서 캐시 동작을 확인한다.

        headers는 baseline 응답의 헤더(대소문자 구분 없이 조회 가능한 딕셔너리류)다 —
        engine.py가 미리 구해둔 공유 baseline의 requests.Response.headers를 그대로
        받거나, 단독 실행 시엔 _probe_page가 직접 받아온 걸 넘겨준다.
        """
        if not headers:
            return None

        etag          = headers.get('ETag', '').strip()
        last_modified = headers.get('Last-Modified', '').strip()

        if not etag and not last_modified:
            return None  # 캐시 헤더 없음

        # CDN / 캐시 레이어 헤더 수집 (초기 응답 기준)
        cdn_headers = {}
        for h in ('X-Cache', 'CF-Cache-Status', 'X-Varnish', 'Age', 'Via', 'X-CDN', 'X-Cache-Hits'):
            val = headers.get(h)
            if val:
                cdn_headers[h] = val

        # 조건부 GET
        cond_headers = {}
        if etag:
            cond_headers['If-None-Match'] = etag
        if last_modified:
            cond_headers['If-Modified-Since'] = last_modified

        try:
            cond_resp = self.session.get(url, headers=cond_headers, timeout=self.TIMEOUT)
            conditional_status = cond_resp.status_code
        except Exception:
            conditional_status = None

        return {
            'etag':               etag or None,
            'etag_type':          self._analyze_etag(etag) if etag else None,
            'last_modified':      last_modified or None,
            'cache_control':      headers.get('Cache-Control') or None,
            'conditional_status': conditional_status,
            'cache_confirmed':    conditional_status == 304,
            'cdn_headers':        cdn_headers if cdn_headers else None,
        }

    def _probe_exposed(self, base_url: str, tech_stack: dict) -> list[dict]:
        """언어/공통 노출 파일 목록을 탐지하고 200/403 응답을 기록한다."""
        language = tech_stack.get('language')
        paths = list(_EXPOSED_PATHS['base'])
        if language and language in _EXPOSED_PATHS:
            paths += _EXPOSED_PATHS[language]

        found = []
        for path in paths:
            url = urljoin(base_url.rstrip('/') + '/', path)
            try:
                resp = self.session.get(url, timeout=self.TIMEOUT, allow_redirects=False)
                if resp.status_code in (200, 403):
                    found.append({
                        'path':   path,
                        'url':    url,
                        'status': resp.status_code,
                        'length': len(resp.text),
                    })
            except Exception:
                pass
        return found

    @staticmethod
    def _analyze_etag(etag: str) -> str:
        """ETag 포맷으로 서버 타입을 추론한다."""
        if etag.startswith('W/'):
            return 'weak'    # Node.js / Express 계열
        raw   = etag.strip('"')
        parts = raw.split('-')
        if len(parts) == 3:
            return 'apache'  # inode-size-mtime 형식
        if len(parts) == 2:
            return 'nginx'   # mtime_hex-size_hex 형식
        return 'unknown'

    def _send(self, url: str, method: str, data: dict) -> tuple[requests.Response | None, float]:
        start = time.monotonic()
        try:
            if method == 'GET':
                resp = self.session.get(url, params=data, timeout=self.TIMEOUT)
            else:
                resp = self.session.request(method, url, data=data, timeout=self.TIMEOUT)
            return resp, time.monotonic() - start
        except Exception:
            return None, time.monotonic() - start

    @staticmethod
    def _record(resp: requests.Response | None, elapsed: float) -> dict:
        if resp is None:
            return {'status': None, 'length': None, 'body': None, 'elapsed': elapsed}
        return {
            'status':  resp.status_code,
            'length':  len(resp.text),
            'body':    resp.text,
            'elapsed': round(elapsed, 3),
        }
