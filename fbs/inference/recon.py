import time
import random
import string
import difflib
import requests
from urllib.parse import urljoin

from fbs.inference.sql_dialects import detect_db_from_error, extract_error_snippet
from fbs.inference.validation import probe_filter_map, detect_waf_body

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
                and length != baseline_length and detect_waf_body(body)
            )
            if blocked_this_quote:
                waf_blocked = True

            error_results[payload] = {
                'status':             probe_status,
                'status_changed':     status_changed,
                'status_signal':      status_signal,
                'length':             length,
                'length_delta':       length_delta,
                'probe_like_default': probe_like_default,
                'default_similarity': default_similarity,
                'error_snippet':      extract_error_snippet(body) if db_type else None,
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

        # 반사 신호 — 이 필드가 응답에 그대로 반사되는지/어느 HTML 컨텍스트인지/꺾쇠가
        # 이스케이프 없이 사는지를 한 번에 측정한다. 모든 전략의 공용 신호(XSS는 이걸로
        # 바로 동작하고, SQLi 등은 blind 여부로 쓴다)라 recon에서 한 번만 잰다.
        # filter_map보다 먼저 재서, 필터 지도가 반사형/응답형을 고르는 근거로 쓴다.
        reflection = self.probe_reflection(url, method, data, target)

        # 위 waf_blocked는 '/"만으로 판단해서 SQLi 편향이다 — XSS/SSTI 등 다른 유형만 막는
        # 필터는 따옴표에 반응 안 해서 여기선 안 잡힌다. filter_map은 그것과 별개로, 반사되면
        # 토큰 생존을 직접 측정(반사형), 아니면 거부 지문(응답형)으로 토큰별 outcome을 낸다.
        filter_map = probe_filter_map(self._send, url, method, data, target, baseline_body, BASELINE, reflection)

        return {
            'case':             case,
            'baseline_anomaly': baseline_anomaly,
            'db_hint':          db_hint,
            'quote_char':       triggering_quote,
            'error':            error_results,
            'sqli_signal':      sqli_signal,
            'waf_blocked':      waf_blocked,
            'filter_map':       filter_map,
            'reflection':       reflection,
            # detect_db_from_error()로 이미 확인된 DB 엔진 이름(SQL_DIALECTS의 키와 동일한
            # 표기: SQLite/MySQL/PostgreSQL/MSSQL/Oracle) — 지금까진 db_hint 문구를 만드는
            # 데만 쓰고 버렸는데, sqli.py가 재탐지 없이 그대로 재사용할 수 있게 노출한다.
            'detected_db':      detected_db,
        }

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

    # ── 반사 신호 (모든 전략 공용 / recon 측은 층1·2까지만) ──────────────────────
    #
    # XSS 반사 탐지는 3층으로 나뉘는데, recon은 '싼 신호' 두 층만 책임진다(비싼 렌더는 XSS
    # strategy의 몫). SQLi가 recon의 따옴표 프로브로 '관여 신호'만 받고 실제 탐지는 strategy가
    # 하는 것과 같은 경계다.
    #   층1 서버 반사 : 중립 코어가 서버 응답(requests)에 그대로 박히나 + 컨텍스트 + 꺾쇠 생존
    #   층2 DOM 정적  : 서버엔 없어도 원본 HTML에 'URL 소스→위험 싱크' 패턴이 있으면 DOM 반사 의심
    #   층3 렌더(X)   : Playwright로 실제 DOM 반사·실행을 확정 — 비싸고 XSS 전용이라 strategy가 함
    #
    # probe_reflection() 하나가 층1·2를 한 번에 재서 '반사 신호' 딕셔너리로 돌려준다.

    # 층1에서 생존을 측정하는 메타문자. 따옴표(',")는 문자열 컨텍스트 SQL을 깨서 반사 자체를
    # 못 보게 만들 수 있으므로(=반사 사이트를 blind로 오판) 넣지 않고 꺾쇠만 잰다. 따옴표 생존은
    # XSS strategy가 페이로드를 실제로 쏴 보고 exec_sig로 확인한다.
    _REFLECT_METACHARS = ('<', '>')

    # 층2에서 찾는 DOM 반사 패턴: JS가 URL 등에서 입력을 읽는 '소스' → 위험 '싱크'로 흘리는 꼴.
    # 서버 HTML엔 입력이 안 보여도(requests로 반사 X) 브라우저에선 JS가 DOM에 주입한다.
    _DOM_SOURCES = ('location.search', 'location.hash', 'location.href',
                    'document.url', 'document.documenturi', 'urlsearchparams')
    _DOM_SINKS = ('innerhtml', 'outerhtml', 'insertadjacenthtml',
                  'document.write', 'eval(')

    def probe_reflection(self, url: str, method: str, data: dict, target: str) -> dict | None:
        """이 필드의 '반사 신호'를 한 번에 잰다 — 층1(서버 반사) + 층2(DOM 정적 의심).

        중립 코어(영숫자) 뒤에 'LT<GT>'를 붙여 보낸다. 따옴표가 없어 문자열 컨텍스트 SQL을
        깨지 않으므로, 반사 사이트를 500 에러로 blind 오판하지 않는다.

        반환(None=요청 실패/WAF 차단으로 판정 불가):
          층1 성공 → {'reflected': True,  'contexts': [...], 'survived': [...], 'tested': ['<','>']}
          층1 실패 → {'reflected': False, 'contexts': [], 'survived': [], 'tested': ['<','>'],
                      (층2 적중 시) 'dom_suspect': True, 'dom_source': ..., 'dom_sink': ...}
        """
        core = 'fbsr' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        resp, _elapsed, _err = self._send(url, method, {**data, target: f"{core}LT<GT>"})
        if resp is None:
            return None
        body = resp.text
        if detect_waf_body(body):
            return None
        tested = list(self._REFLECT_METACHARS)

        # 층1 — 서버 반사: 코어가 서버 응답에 그대로 박혔나 + 컨텍스트 + 꺾쇠 생존
        if core in body:
            survived = [c for c, label in (('<', 'LT<'), ('>', 'GT>')) if label in body]
            return {'reflected': True, 'contexts': self._reflection_contexts(body, core),
                    'survived': survived, 'tested': tested}

        # 층2 — DOM 정적: 서버엔 없지만 원본 HTML에 'URL 소스→위험 싱크'가 같이 있으면 DOM 반사
        # 의심. 소스·싱크 공존만 보는 휴리스틱이라(실제 연결은 미확인) '의심 깃발'일 뿐 — 확정은
        # XSS strategy의 브라우저 렌더(층3)가 한다.
        result = {'reflected': False, 'contexts': [], 'survived': [], 'tested': tested}
        low = body.lower()
        src  = next((s for s in self._DOM_SOURCES if s in low), None)
        sink = next((k for k in self._DOM_SINKS   if k in low), None)
        if src and sink:
            result.update({'dom_suspect': True, 'dom_source': src, 'dom_sink': sink})
        return result

    def _reflection_contexts(self, body: str, marker: str) -> list[str]:
        """marker가 반사된 모든 위치의 HTML 컨텍스트를 분류한다. raw 문자열을 파서에 넣으면
        주입 마커가 파싱을 깨서 위치를 잃기 쉬우므로, marker 인덱스 주변 원문을 직접 스캔하는
        휴리스틱으로 분류한다(범용 XSS 스캐너의 고전적 접근)."""
        found = []
        start = 0
        while True:
            i = body.find(marker, start)
            if i == -1:
                break
            found.append(self._classify_one(body, i))
            start = i + len(marker)
        return found or ['html']

    @staticmethod
    def _classify_one(body: str, i: int) -> str:
        before = body[:i]

        # <script> ... </script> 내부?
        s_open = before.rfind('<script')
        s_close = before.rfind('</script')
        if s_open != -1 and s_open > s_close:
            return 'js'

        # <!-- ... --> 주석 내부?
        c_open = before.rfind('<!--')
        c_close = before.rfind('-->')
        if c_open != -1 and c_open > c_close:
            return 'comment'

        last_lt = before.rfind('<')
        last_gt = before.rfind('>')
        if last_lt > last_gt:
            # 태그 여는 '<' 이후 아직 '>'로 안 닫힘 → 태그 내부(속성 영역)
            tag_frag = before[last_lt:]
            # 현재 위치가 열린 따옴표 안인지: 태그 시작 이후 따옴표 개수가 홀수면 그 안쪽
            if tag_frag.count('"') % 2 == 1:
                return 'attr_double'
            if tag_frag.count("'") % 2 == 1:
                return 'attr_single'
            return 'attr_unquoted'

        # 그 외 — 태그 사이 일반 텍스트
        return 'html'

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
        for i, page in enumerate(pages, 1):
            print(f"  [{i}/{len(pages)}] 프로브 중: {page['url']}", flush=True)
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
                    hit = {t: o for t, o in filter_map.items() if o != 'passed'}
                    print(f"    필터 지도 : {len(hit)}/{len(filter_map)}개 토큰 필터됨 — {hit}")
                reflection = db.get('reflection')
                if reflection is None:
                    print(f"    반사 여부 : 측정 불가 (요청 실패 또는 WAF 차단)")
                elif not reflection.get('reflected'):
                    if reflection.get('dom_suspect'):
                        print(f"    반사 여부 : 서버 반사 없음 — DOM 반사 의심 "
                              f"({reflection.get('dom_source')} → {reflection.get('dom_sink')}, "
                              f"브라우저에서 확인 필요)")
                    else:
                        print(f"    반사 여부 : 반사 안 됨 (blind)")
                else:
                    survived = reflection.get('survived') or []
                    tested   = reflection.get('tested') or []
                    ctxs = ', '.join(sorted(set(reflection.get('contexts') or [])))
                    surv = ' '.join(c for c in tested if c in survived) or '없음'
                    print(f"    반사 여부 : 반사됨 | 컨텍스트={ctxs} | 꺾쇠 생존={surv}")
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
            print(f"      · param={param!r} 프로브", flush=True)
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
                print(f"      · form {name!r} 프로브", flush=True)
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
            print(f"      · hidden param={param!r} 프로브", flush=True)
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
            print(f"      · hidden POST {name!r} 프로브", flush=True)
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
