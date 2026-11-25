import time
import difflib
import requests
from urllib.parse import urljoin

from fbs.inference.sql_dialects import detect_db_from_error
from fbs.inference.validation import probe_filter_map, classify_reflected_reaction
from fbs.inference.compare import visible_text, diff_score, volatile_anchors, strip_volatile, probe_token

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

# 노출 파일 catch-all 판정용 길이 임계값 (default 페이지와 이만큼 이내면 실제 파일로 안 본다)
_LENGTH_THRESHOLD = 100


def reflection_contexts(body: str, marker: str) -> list[str]:
    """marker가 반사된 모든 위치의 HTML 컨텍스트(js/comment/attr_*/html)를 분류한다. 마커 주변
    원문을 직접 스캔하는 휴리스틱. XSS 점수의 실행 컨텍스트 판정에 쓴다."""
    found = []
    start = 0
    while True:
        i = body.find(marker, start)
        if i == -1:
            break
        found.append(_classify_one(body, i))
        start = i + len(marker)
    return found or ['html']


def _classify_one(body: str, i: int) -> str:
    before = body[:i]
    s_open = before.rfind('<script'); s_close = before.rfind('</script')
    if s_open != -1 and s_open > s_close:
        return 'js'
    c_open = before.rfind('<!--'); c_close = before.rfind('-->')
    if c_open != -1 and c_open > c_close:
        return 'comment'
    last_lt = before.rfind('<'); last_gt = before.rfind('>')
    if last_lt > last_gt:
        tag_frag = before[last_lt:]
        if tag_frag.count('"') % 2 == 1:
            return 'attr_double'
        if tag_frag.count("'") % 2 == 1:
            return 'attr_single'
        return 'attr_unquoted'
    return 'html'


# 층2 DOM 반사 패턴: JS가 URL 등에서 입력을 읽는 소스 → 위험 싱크로 흘리는 꼴.
_DOM_SOURCES = ('location.search', 'location.hash', 'location.href',
                'document.url', 'document.documenturi', 'urlsearchparams')
_DOM_SINKS = ('innerhtml', 'outerhtml', 'insertadjacenthtml',
              'document.write', 'eval(')

# 반사형 라벨(서버 반사가 되는 필드 종류). 꺾쇠 등 XSS 프로브는 이 라벨에서만 의미.
_REFLECT_LABELS = ('memo', 'search', 'simple')

# 2b 적대적 프로브 허용 규칙 — 기본은 "다 보낸다", 그 라벨에서 의미 없는 것만 뺀다.
# (filter_map, quotes, angle<>)  라벨별로 켜고 끄는 걸 여기 한곳에서 관리한다.
#   filter_map : 메모(이전 입력이 쌓여 거부/생존 측정이 오염됨)만 끔
#   quotes     : SQLi는 반사와 직교 → 모든 라벨 허용
#   angle(<>)  : 반사형(memo/search/simple)일 때만 — 반사 안 되는데 XSS 꺾쇠는 낭비
_PROBE_RULES = {
    # label        filter_map  quotes  angle
    'memo':       (False,      True,   True),
    'search':     (True,       True,   True),
    'simple':     (True,       True,   True),
    'stateful':   (True,       True,   False),
    'blind':      (True,       True,   False),
}


class Recon:
    TIMEOUT = 10

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    # ── 필드 측정(Phase 0~3) + 2b ───────────────────────────────────────────────
    # 공격 전략을 고르기 전에, 페이지가 입력에 어떻게 반응하는지로 필드 종류를 가른다. 이 측정이 recon의
    # 본체다(별도 분류 패스 없음) — _probe_page가 필드마다 _classify_surface를 돌려 db dict를 만든다.
    # 모든 판정의 기준은 처음 잰 reload_noise(페이지 자체의 동적 노이즈) 하나뿐이고 고정 임계는 안 쓴다.
    # 비교는 직전 관측 대비, 무변화는 종료하지 않고 다음 단계로 흘려보낸다.
    #   Phase 0 : 제출 없이 GET 2번 → reload_noise(바닥) + 기준 텍스트.
    #   Phase 1 : 빈 값 → 이탈 여부 + 관측(무변화여도 종료 X).
    #   Phase 2a: 토큰 → 직전(빈 값) 대비 변화. 둘 다 바닥 못 넘으면 미확정(라벨 비움).
    #   Phase 3 : 반응 있으면 성격 분류 — 반사형(메모/검색/단순) / stateful / 입력민감·결정적(blind).
    #   2b      : filter_map → 따옴표(',") → (반사 필드) 꺾쇠 생존.

    def _classify_surfaces(self, page: dict, base_url: str) -> list[tuple]:
        """분류할 입력면을 (action, method, 형제필드, 타겟필드)로 모은다. 형제필드는 타겟만
        프로브로 바꿔 보낼 때 같이 채워 보내는 나머지 필드다(폼이 요구하는 값 유지용). recon 본
        루프와 동일하게 쿼리 파라미터·폼 필드에 더해 퍼징으로 찾은 히든 파라미터까지 포함한다."""
        out = []
        seen = set()

        def add(action, method, siblings, target):
            key = (action, method, target)
            if target and key not in seen:
                seen.add(key)
                out.append((action, method, siblings, target))

        for param in (page.get('params') or {}):
            add(base_url, 'GET', {}, param)
        for form in (page.get('forms') or []):
            action = form.get('action') or page['url']
            method = form.get('method', 'GET').upper()
            # 형제 필드는 빈 값이 아니라 non-empty 기본값으로 채운다 — 멀티필드 폼(로그인 등)은
            # 다른 필드가 비어 있으면 "값을 입력하세요" 단계에서 멈춰 제출 자체가 발화하지 않아
            # 상태 변화(로그인 카운터 등)를 못 본다. 크롤러·전략과 동일하게 캡처값 없으면 'test'로 채운다.
            inputs = {
                inp['name']: (inp.get('value') or 'test')
                for inp in form.get('inputs', []) if inp.get('name')
            }
            for inp in form.get('inputs', []):
                name = inp.get('name')
                if not name or inp.get('type') in ('submit', 'button', 'image', 'reset'):
                    continue
                add(action, method, {k: v for k, v in inputs.items() if k != name}, name)
        for param in (page.get('hidden_params') or []):
            add(base_url, 'GET', {}, param)
        for entry in (page.get('hidden_post_params') or []):
            action = entry.get('action') or page['url']
            add(action, 'POST', dict(entry.get('known_fields') or {}), entry.get('param'))
        return out

    @staticmethod
    def _probe_token() -> str:
        """반사 여부를 보려고 보내는 프로브. 필터·SQL에 안 걸리는 영숫자라, 응답에 이 토큰이
        그대로 박혀 있으면 입력이 반사된 것으로 본다. fbsrf 접두어로 recon 반사 프로브임을 표식."""
        return probe_token('fbsrf')

    @staticmethod
    def _added_text(base: str, cur: str, max_len: int = 120) -> str:
        """cur에서 base 대비 새로 생긴 텍스트만 뽑는다 — 빈 값/토큰 응답에서 나오는 안내 문구
        같은 힌트를 모으는 용도. 글자 단위 diff는 base에 우연히 있는 같은 글자를 공통으로 매칭해
        단어를 조각내므로(예: Good → Gd), 바뀐 구간을 양옆 공백까지 넓혀 단어를 통째로 뽑는다."""
        if not cur or cur == base:
            return ''
        matcher = difflib.SequenceMatcher(None, base, cur, autojunk=False)
        parts, last_end = [], 0
        for tag, _, _, j1, j2 in matcher.get_opcodes():
            if tag not in ('insert', 'replace'):
                continue
            # 구간 양끝의 공백을 먼저 벗겨 단어 경계에서 시작/끝나게 한다(안 그러면 앞뒤 기존 단어까지 딸려옴).
            while j1 < j2 and cur[j1].isspace():
                j1 += 1
            while j2 > j1 and cur[j2 - 1].isspace():
                j2 -= 1
            if j1 >= j2:
                continue
            # 남은 구간을 양옆 비공백까지 넓혀 단어를 통째로 잡는다.
            while j1 > 0 and not cur[j1 - 1].isspace():
                j1 -= 1
            while j2 < len(cur) and not cur[j2].isspace():
                j2 += 1
            j1 = max(j1, last_end)   # 이전에 넓혀 뽑은 단어와 겹치지 않게
            if j1 >= j2:
                continue
            parts.append(cur[j1:j2])
            last_end = j2
        added = ' '.join(p.strip() for p in parts if p.strip()).strip()
        return added[:max_len] if added else ''

    @staticmethod
    def _fmt_filter(filter_map: dict | None) -> str | None:
        """필터 지도를 사람이 읽기 좋게 압축한다 — 원시 dict 대신 outcome별로 토큰을 묶고, 공백
        토큰은 ␣로 보인다. 예: {"'":'rejected', ' ':'rejected'} → "2/44 차단  rejected ← ' ␣"."""
        if not filter_map:
            return None
        hit = {t: o for t, o in filter_map.items() if o != 'passed'}
        if not hit:
            return None
        by_outcome: dict[str, list[str]] = {}
        for t, o in hit.items():
            by_outcome.setdefault(o, []).append('␣' if t == ' ' else t)
        groups = ' / '.join(f"{o} ← {' '.join(ts)}" for o, ts in by_outcome.items())
        return f"{len(hit)}/{len(filter_map)} 차단  {groups}"

    @staticmethod
    def _dom_suspect(body: str) -> tuple[str, str] | None:
        """서버 응답엔 토큰이 안 박혔어도, 원본 HTML에 URL 소스(location.search 등)→위험 싱크
        (innerHTML 등)가 같이 있으면 DOM 기반 반사 의심. 공존만 보는 휴리스틱(층2)이라 의심
        깃발일 뿐 — 실제 실행 확정은 브라우저 렌더(층3) = XSS 전략 몫이다. 반환: (src, sink) | None."""
        low = body.lower()
        src  = next((s for s in _DOM_SOURCES if s in low), None)
        sink = next((k for k in _DOM_SINKS   if k in low), None)
        return (src, sink) if src and sink else None

    def _classify_surface(self, action: str, method: str, siblings: dict, target: str,
                          get_floor: int, get_base_text: str, get_anchors: list,
                          base_url: str) -> tuple[str, str, dict]:
        """직전 관측 대비 변화가 바닥(floor)을 넘는지만으로 종류를 가른다. 고정 임계는 없다.
        바닥·마스킹 앵커는 엔드포인트별로 잡는다 — GET 랜딩이면 Phase 0에서 온 GET 값을 재사용하고,
        그 외 엔드포인트(POST·다른 action)는 빈 값을 2번 보내 그 엔드포인트의 양성 변동 앵커와 바닥을
        따로 잰다(빈 값은 검증에서 걸려 state를 안 건드려 양성 기준이 된다). GET는 Phase 0에서 하던
        동적 구간 마스킹을, POST 응답에도 대칭으로 적용하기 위함.
        base_text(반응 게이트 기준)는 어느 경우든 GET 랜딩이다 — 빈 제출이 로드와 달라졌는지를 봐야 한다.
        측정(Phase 1→2a→3)으로 성격을 가른 뒤, 반응 있은 필드만 2b(적대적 프로브)를 돌린다.
        반환: (판정 문자열, 힌트 문자열, db dict). db는 소비처가 읽는 구조화 결과
        {label, db_hint, quote_char, sqli_signal, detected_db, filter_map, reflection}."""
        base_text = get_base_text
        hints: list[str] = []

        def harvest(text):
            snip = self._added_text(base_text, text)
            if snip and snip not in hints:
                hints.append(snip)

        def done(verdict, label='', *, reflection=None, adv=None):
            a = adv or {}
            if a.get('detected_db'):
                db_hint = '에러 시그니처 확인 (DB 존재)'
            elif a.get('sqli_signal'):
                db_hint = '반응이 다름 (재검증 필요)'
            else:
                db_hint = '반응이 없음 (파라미터화/필터/DB 없음 등)'
            db = {
                'label':       label,
                'db_hint':     db_hint,
                'quote_char':  a.get('quote_char'),
                'sqli_signal': a.get('sqli_signal', False),
                'detected_db': a.get('detected_db'),
                'filter_map':  a.get('filter_map'),
                'reflection':  reflection,
            }
            return verdict, (' | '.join(hints)[:200] if hints else ''), db

        # Phase 1 — 빈 값: 이탈 여부만 먼저 확정하고, 아니면 관측만 하고 다음 단계로(무변화여도 종료 X).
        empty, _ = self._send(action, method, {**siblings, target: ''})
        if empty is not None and 300 <= empty.status_code < 400:
            return done(f"이탈형: 빈 값 → {empty.status_code} {empty.headers.get('Location')}", 'redirect')

        # 엔드포인트 양성 베이스라인 — GET 랜딩은 Phase 0 재사용, 그 외는 빈 값을 한 번 더 보내 이
        # 엔드포인트의 변동 앵커(GET 앵커와 합집합)와 바닥을 잰다. 빈 값 요청이 아예 실패했으면 GET으로 폴백.
        if empty is None or (action == base_url and method == 'GET'):
            anchors, floor = get_anchors, get_floor
        else:
            empty2, _ = self._send(action, method, {**siblings, target: ''})
            raw1 = visible_text(empty.text)
            raw2 = visible_text(empty2.text) if empty2 is not None else raw1
            anchors = get_anchors + volatile_anchors(raw1, raw2)
            floor = diff_score(strip_volatile(raw1, anchors), strip_volatile(raw2, anchors))

        def clean(resp):
            # 반사(토큰 박힘)는 원문으로 보고, diff 비교는 동적 구간 제거한 텍스트로 한다.
            return strip_volatile(visible_text(resp.text), anchors) if resp is not None else ''

        empty_text = clean(empty)
        harvest(empty_text)
        d_empty = diff_score(base_text, empty_text)   # 빈 제출이 평소 페이지를 움직였나

        # Phase 2a — 중립 토큰: 직전(빈 값) 대비 변화를 본다. reload_noise는 바닥.
        tok1 = self._probe_token()
        r1, _ = self._send(action, method, {**siblings, target: tok1})
        if r1 is None:
            return done("측정 불가: 요청 실패", 'error')
        if 300 <= r1.status_code < 400:
            return done(f"이탈형: 프로브 → {r1.status_code} {r1.headers.get('Location')}", 'redirect')
        body1  = r1.text                # 반사 판정용 원문
        t1_text = clean(r1)             # diff 비교용(동적 구간 제거)
        harvest(t1_text)
        d_token = diff_score(empty_text, t1_text)     # 토큰이 빈 값 대비 응답을 바꿨나

        # 반응 게이트: 빈 값이든 토큰이든 바닥을 넘게 움직였나? 전부 아니면 미확정(비워두고 끝).
        # 중립 반응만으론 stub/인증벽으로 확정할 수 없다 — 그 처리는 나중에 결과 보고 결정한다.
        reacted = not (d_empty <= floor and d_token <= floor
                       and diff_score(base_text, t1_text) <= floor)
        if not reacted:
            return done('')          # 미확정 — 라벨 없음

        # Phase 3 — 반응 있음. 변화의 성격을 가르고 라벨을 정한다.
        reflected = tok1 in body1          # 층1: 서버 응답에 그대로 박힘
        dom = None
        if reflected:
            tok2 = self._probe_token()
            r2, _ = self._send(action, method, {**siblings, target: tok2})
            body2 = r2.text if r2 is not None else ''   # 반사 판정용 원문
            harvest(clean(r2))
            if tok1 in body2:
                label, text = 'memo', "반사형 · 메모: 다른 입력을 보내도 이전 값이 남음(입력이 쌓임)"
            elif tok1 in t1_text:          # 눈에 보이는 본문에 박힘
                label, text = 'search', "반사형 · 검색: 입력이 본문에 그대로 반사됨"
            else:
                label, text = 'simple', "반사형 · 단순반사: 입력이 속성/스크립트 등 제한된 위치에만 반사됨"
        else:
            # 층2: 서버 반사는 없지만 URL 소스→위험 싱크(innerHTML 등) 공존 → DOM 반사 의심
            dom = self._dom_suspect(body1)   # (src, sink) | None
            r1b, _ = self._send(action, method, {**siblings, target: tok1})
            d_repeat = diff_score(t1_text, clean(r1b))
            if d_repeat > floor:
                label, text = 'stateful', f"상태형(stateful): 같은 입력에도 응답이 계속 변함 (반복 diff={d_repeat} > 바닥 {floor})"
            else:
                label, text = 'blind', f"입력민감·결정적(blind): 입력엔 반응하나 같은 입력엔 고정 (토큰 diff={d_token}, 반복 diff={d_repeat}, 바닥 {floor})"
            if dom:
                text += f" | DOM 반사 의심({dom[0]}→{dom[1]})"

        # 2b — 적대적 프로브 (반응 있은 필드만). 어떤 프로브를 보낼지는 라벨별 _PROBE_RULES가 정한다.
        # anchor는 2a에서 이미 반사됨을 측정한 tok1을 그대로 넘긴다(새 고정값 대신 측정된 값 재사용).
        adv = self._adversarial_probes(action, method, siblings, target, label, base_text, floor, tok1)

        # reflection dict 조립 — reflected/survived/dom은 위 측정값 그대로, contexts만 분류기로 추가.
        if reflected:
            reflection = {'reflected': True, 'contexts': reflection_contexts(body1, tok1),
                          'survived': adv['survived'], 'tested': ['<', '>']}
        else:
            reflection = {'reflected': False, 'contexts': [], 'survived': [], 'tested': ['<', '>']}
            if dom:
                reflection.update({'dom_suspect': True, 'dom_source': dom[0], 'dom_sink': dom[1]})

        summary = self._adv_summary(adv)
        verdict = text + (f"  ▶ 2b: {summary}" if summary else '')
        return done(verdict, label, reflection=reflection, adv=adv)

    def _adversarial_probes(self, action: str, method: str, siblings: dict, target: str,
                            label: str, baseline_body: str, noise: int, token: str) -> dict:
        """2b — filter_map / 따옴표(',") / 꺾쇠 생존. 어떤 프로브를 보낼지는 라벨별 _PROBE_RULES로
        정한다(기본은 다 보냄, 의미 없는 것만 뺌). 구조화된 신호 dict를 돌려준다.
        token은 2a에서 반사됨을 측정한 그 프로브(tok1)로, filter_map·꺾쇠의 anchor로 재사용한다.
        반환: {filter_map, sqli_signal, detected_db, quote_char, survived}."""
        allow_fmap, allow_quotes, allow_angle = _PROBE_RULES.get(label, (True, True, False))
        reflected = label in _REFLECT_LABELS
        result = {'filter_map': None, 'sqli_signal': False, 'detected_db': None,
                  'quote_char': None, 'survived': []}

        # ① filter_map — 메모면 이전 입력이 쌓여 거부/생존 측정이 오염되므로 규칙에서 끔.
        if allow_fmap:
            def send3(u, m, d):
                r, _ = self._send(u, m, d)
                return r, 0, None
            result['filter_map'] = probe_filter_map(send3, action, method, siblings, target,
                                                    baseline_body, token, noise, {'reflected': reflected})
        fmap = result['filter_map'] or {}

        # ② 따옴표 ',\" (모든 라벨) — filter_map에서 막힌 따옴표는 배제, 통과한 것만 관측.
        # 에러 기반 SQLi는 200으로 내려오며 본문에 SQL 에러를 뱉는 게 가장 흔하므로, 상태코드와
        # 무관하게 본문 에러 시그니처(detect_db_from_error)를 보고, 500은 별도 신호로 더한다.
        # 단 baseline에도 같은 시그니처가 있으면 그 페이지 native 콘텐츠라 신호가 아니다(baseline 차분).
        base_db = detect_db_from_error(baseline_body or '') if allow_quotes else None
        if allow_quotes:
            for q in ("'", '"'):
                if fmap.get(q, 'passed') != 'passed':
                    continue
                r, _ = self._send(action, method, {**siblings, target: q})
                if r is None:
                    continue
                db = detect_db_from_error(r.text)
                if db == base_db:        # baseline에 이미 있던 시그니처 → 반응 아님
                    db = None
                if not (db or r.status_code >= 500):
                    continue
                result['sqli_signal'] = True
                if result['quote_char'] is None:
                    result['quote_char'] = q
                if db and not result['detected_db']:
                    result['detected_db'] = db

        # ③ 꺾쇠 <> 생존 — 반사형 라벨에서만(반사 안 되는데 XSS 프로브는 낭비). 응답 전체엔 태그 때문에
        # <>가 늘 있으므로, 토큰(앵커) 바로 뒤에 우리가 보낸 <>가 이스케이프 없이 그대로 반사됐을 때만
        # 생존으로 본다(classify_reflected_reaction이 passed/encoded/removed를 가른다).
        if allow_angle:
            r, _ = self._send(action, method, {**siblings, target: f"{token}<>"})
            if r is not None and classify_reflected_reaction(r.text, token, '<>') == 'passed':
                result['survived'] = ['<', '>']

        return result

    @staticmethod
    def _adv_summary(adv: dict) -> str:
        """2b 구조화 신호를 사람이 읽는 한 줄로 요약(출력용)."""
        out = []
        fmap = adv.get('filter_map')
        if fmap:
            hit = {t: o for t, o in fmap.items() if o != 'passed'}
            out.append(f"필터 {len(hit)}/{len(fmap)}개 막힘: {hit}")
        if adv.get('detected_db'):
            out.append(f"error-based SQLi 확정({adv.get('quote_char')!r}, DB={adv['detected_db']})")
        elif adv.get('sqli_signal'):
            out.append(f"{adv.get('quote_char')!r}→500 (SQLi 우선순위↑)")
        if adv.get('survived'):
            out.append(f"<> 생존: {' '.join(adv['survived'])}")
        return ' | '.join(out)

    def run(self, pages: list[dict]) -> list[dict]:
        """각 페이지의 모든 필드에 baseline 값을 전송하고 응답을 page['recon']에 저장한다."""
        print(f"\n# [리콘] {len(pages)}개 페이지 프로브 시작")
        for i, page in enumerate(pages, 1):
            print(f"  [{i}/{len(pages)}] 프로브 중: {page['url']}", flush=True)
            page['recon'] = self._probe_page(page)

        for page in pages:
            recon  = page['recon']
            default = recon.get('__default__', {})
            methods = recon.get('__methods__') or {}
            method_str = ' '.join(methods.get('allow') or []) or '—'
            print(f"\n── {page['url']}   {default.get('status')} · {default.get('length')}B · {method_str}")

            psig = page.get('page_signals') or {}
            redir = psig.get('redirect')
            if redir or psig.get('gate_hints'):
                parts = []
                if redir:
                    parts.append(f"로드 시 이탈({redir.get('kind')}→{redir.get('target')})")
                if psig.get('gate_hints'):
                    parts.append(f"요구 추정 {psig['gate_hints']}")
                print(f"  페이지 신호 : {' | '.join(parts)}")
            for entry in (recon.get('__exposed__') or []):
                flag = '★' if entry['status'] == 200 else '△'
                note = '접근 차단' if entry['status'] == 403 else f"{entry['length']}B"
                print(f"  {flag} 노출 파일 : {entry['path']} → {entry['status']} ({note})")

            for field, data in recon.items():
                if field in ('__default__', '__exposed__', '__methods__'):
                    continue
                db    = data.get('db', {})
                label = db.get('label') or '미확정'

                # redirect/error/미확정은 라벨만으론 부족해 verdict(목적지·사유)를 그대로 보인다.
                if label in ('redirect', 'error', '미확정', ''):
                    print(f"  [{field}] {data.get('verdict') or label or '미확정'}")
                    continue

                # SQLi 신호는 라벨 옆에 한눈에.
                if db.get('detected_db'):
                    sig = f"   ★ SQLi: {db['detected_db']} 에러 (따옴표 {db.get('quote_char')!r})"
                elif db.get('sqli_signal'):
                    sig = f"   ★ SQLi: 따옴표 {db.get('quote_char')!r} → 500"
                else:
                    sig = ''
                print(f"  [{field}] {label}{sig}")

                if data.get('hint'):
                    print(f"      힌트 : {data['hint']}")
                fm = self._fmt_filter(db.get('filter_map'))
                if fm:
                    print(f"      필터 : {fm}")
                refl = db.get('reflection') or {}
                if refl.get('reflected'):
                    ctxs = ', '.join(sorted(set(refl.get('contexts') or []))) or '없음'
                    surv = ' '.join(c for c in (refl.get('tested') or [])
                                    if c in (refl.get('survived') or [])) or '없음'
                    print(f"      반사 : 반사됨 | 컨텍스트={ctxs} | 꺾쇠 생존={surv}")
                elif refl.get('dom_suspect'):
                    print(f"      반사 : 서버 반사 없음 — DOM 반사 의심 "
                          f"({refl.get('dom_source')}→{refl.get('dom_sink')}, 브라우저 확인 필요)")
        return pages

    def _probe_page(self, page: dict) -> dict:
        results = {}
        base_url = page['url'].split('?')[0]

        results['__methods__'] = self._probe_methods(base_url)   # OPTIONS — baseline 불필요

        # Phase 0 — 제출 없는 GET ×2. 첫 응답이 곧 baseline(= __default__ + page['_baseline'], 뒤의
        # WafDetector가 재사용). 두 응답을 비교해 요청마다 바뀌는 구간(광고·타임스탬프 등)을 앵커로 뽑아
        # page['_volatile']에 저장하고, 그 구간을 뺀 텍스트로 reload_noise(바닥)를 잰다. 이하 모든 필드
        # 측정이 같은 앵커로 변동 구간을 제거한 뒤 비교한다. baseline은 따로 또 안 받는다.
        r1, elapsed = self._send(base_url, 'GET', {})
        r2, _       = self._send(base_url, 'GET', {})
        body1 = r1.text if r1 is not None else None
        raw1 = visible_text(body1) if body1 is not None else ''
        raw2 = visible_text(r2.text) if r2 is not None else ''
        anchors = volatile_anchors(raw1, raw2)
        page['_volatile'] = anchors
        base_text = strip_volatile(raw1, anchors)
        reload_noise = diff_score(base_text, strip_volatile(raw2, anchors))
        if anchors:
            print(f"  [노이즈 제외] {len(anchors)}개 동적 구간 마스킹:")
            for anc in anchors:
                print(f"      · …{anc['prefix'][-15:]}❲{anc['sample']}❳{anc['suffix'][:15]}…")
        page['_baseline'] = {
            'status':  r1.status_code if r1 is not None else None,
            'body':    body1,
            'headers': r1.headers if r1 is not None else {},
            'elapsed': elapsed,
        }
        results['__default__'] = {
            'status':  page['_baseline']['status'],
            'length':  len(body1) if body1 is not None else None,
            'body':    body1,
            'elapsed': elapsed,
        }
        default_length = results['__default__']['length']

        results['__exposed__'] = self._probe_exposed(base_url, page.get('tech_stack') or {}, default_length)

        # 필드마다: baseline 기록 + 측정(Phase 1→2a→3)/2b(= _classify_surface)로 db dict 생성.
        # 입력면은 _classify_surfaces가 params·폼필드·히든(GET/POST)을 한 번에 모은다(중복 제거).
        field_class = page.setdefault('field_class', {})
        for action, method, siblings, target in self._classify_surfaces(page, base_url):
            verdict, hints, db = self._classify_surface(
                action, method, siblings, target, reload_noise, base_text, anchors, base_url)
            # 필드 상세는 run()의 요약에서 한 번만 출력한다(라이브 중복 제거). 요약이 읽도록
            # verdict(redirect/미확정 등 라벨만으론 부족한 경우 표시용)와 hint를 결과에 실어둔다.
            results[target] = {'db': db, 'verdict': verdict, 'hint': hints}
            field_class[(action, method, target)] = db['label']

        return results

    def _probe_exposed(self, base_url: str, tech_stack: dict, default_length: int | None = None) -> list[dict]:
        """언어/공통 노출 파일 목록을 탐지하고 200/403 응답을 기록한다.

        단, 서버가 뭘 요청하든 같은 페이지를 주는 catch-all(존재하지 않는 경로도 200 + 기본 페이지
        본문)이면 모든 경로가 200으로 떠서 전부 오탐이 된다 — 그래서 default 페이지와 길이가 비슷한
        200은 실제 노출 파일이 아니라고 보고 제외한다. 403은 파일이 존재하나 접근 차단이라 유의미하므로
        그대로 기록한다."""
        language = tech_stack.get('language')
        paths = list(_EXPOSED_PATHS['base'])
        if language and language in _EXPOSED_PATHS:
            paths += _EXPOSED_PATHS[language]

        found = []
        for path in paths:
            url = urljoin(base_url.rstrip('/') + '/', path)
            try:
                resp = self.session.get(url, timeout=self.TIMEOUT, allow_redirects=False)
                status = resp.status_code
                if status == 403:
                    found.append({'path': path, 'url': url, 'status': 403, 'length': len(resp.text)})
                elif status == 200:
                    length = len(resp.text)
                    # default와 길이가 비슷하면 catch-all 응답(실제 파일 아님) → 제외
                    if default_length is None or abs(length - default_length) > _LENGTH_THRESHOLD:
                        found.append({'path': path, 'url': url, 'status': 200, 'length': length})
            except Exception:
                pass
        return found

    def _send(self, url: str, method: str, data: dict) -> tuple[requests.Response | None, float]:
        # allow_redirects=False — 탐지 측정은 리다이렉트를 따라가지 않고 raw로 본다(raw 관측).
        start = time.monotonic()
        try:
            if method == 'GET':
                resp = self.session.get(url, params=data, timeout=self.TIMEOUT, allow_redirects=False)
            else:
                resp = self.session.request(method, url, data=data, timeout=self.TIMEOUT, allow_redirects=False)
            return resp, time.monotonic() - start
        except Exception:
            return None, time.monotonic() - start

    def _probe_methods(self, url: str) -> dict | None:
        """OPTIONS로 엔드포인트가 허용하는 HTTP 메소드를 파악한다(응답의 Allow 헤더). 서버가 Allow를
        안 주면(또는 요청 실패) None = 모름. 여기선 허용 메소드 목록만 수집한다 — 실제로 다른 verb를
        찔러보는 변조/우회는 전략 단계의 몫이다."""
        resp, _ = self._send(url, 'OPTIONS', {})
        if resp is None:
            return None
        allow = resp.headers.get('Allow') or resp.headers.get('allow')
        if not allow:
            return None
        methods = sorted({m.strip().upper() for m in allow.split(',') if m.strip()})
        return {'status': resp.status_code, 'allow': methods}
