import re

import requests

from fbs.inference.sql_dialects import detect_db_from_error
from fbs.inference.compare import visible_text, diff_score

"""
입력 검증(input validation) 탐지 공용 모듈 — 앱 필터든 WAF든 "내가 보낸 입력에 앞단이
어떻게 반응하나"를 재는 하나의 일로 통합한다. (예전 waf.py + recon의 필터맵 코어를 합침.)

핵심 원칙은 **baseline 차분**: "본문에 차단 문구가 있나"(절대값)가 아니라 "정상 응답 대비
반응이 바뀌었나"로 본다 — 정상 페이지가 자기 소스에 가진 문구('Access denied' 같은)를
WAF로 오탐하던 문제를 구조적으로 제거한다. "필터냐 WAF냐"는 이 측정 위에 얹는 해석일 뿐.

구성:
  - 반응 프리미티브: classify_reflected_reaction()(반사형 passed/removed/encoded/rejected),
    reduce_substring_bans(), FILTER_PROBE_TOKENS(프로브 vocabulary)
  - 차단 판별: classify_waf_block()(baseline 받으면 차분 게이팅), WafDetector(페이지 passive
    지문 + 양성-상태코드 가드된 active)
  - 귀속: KNOWN_WAF_SIGNATURES(헤더/쿠키 passive), BLOCK_PAGE_SIGNATURES/GENERIC_BLOCK_KEYWORDS
  - 우회: EVASION_TRANSFORMS / XSS_EVASION_TRANSFORMS / try_evade()
  - 비교 유틸: visible_text() / diff_score()

여기 모아둔 이유: recon(DBDetect, 동기 requests)·scanner.py(비동기 Scrapy)·SQLiStrategy/
XSSStrategy가 전부 같은 측정 로직을 써야 신호가 일관되기 때문. recon은 FILTER_PROBE_TOKENS·
반응 분류기·GENERIC_BLOCK_KEYWORDS를 그대로 공유하고(별도 테이블 폐지), 결과는
surface.extra(filter_map/waf_info)로 profiler/strategy에 흐른다.
"""

# ── 시그니처 (web_scanner/pipelines/waf.py에서 그대로 포팅) ─────────────────────

KNOWN_WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
        'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
        'server':  ['cloudflare'],
    },
    'AWS WAF / CloudFront': {
        'headers': ['x-amzn-waf-action', 'x-amz-cf-id', 'x-amz-cf-pop'],
        'cookies': ['awsalb', 'awsalbcors'],
        'server':  ['amazons3', 'cloudfront'],
    },
    'Akamai': {
        'headers': ['x-akamai-transformed', 'akamai-ghost-ip', 'x-akamai-request-id'],
        'cookies': ['akamai_', 'ak_bmsc', 'bm_sv'],
        'server':  ['akamaighost', 'akamaighostd'],
    },
    'Imperva / Incapsula': {
        'headers': ['x-iinfo'],
        'cookies': ['incap_ses_', 'visid_incap_', '__incapsula'],
        'server':  ['incapsula'],
    },
    'ModSecurity': {
        'headers': ['x-modsecurity-id', 'x-modsecurity-error-type'],
        'cookies': [],
        'server':  ['mod_security', 'modsecurity'],
    },
    'F5 BIG-IP ASM': {
        'headers': ['x-wa-info', 'x-cnection'],
        'cookies': ['ts', 'bigipserver', 'f5_cspm'],
        'server':  ['bigip', 'f5'],
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'cookies': ['sucuri_'],
        'server':  ['sucuri'],
    },
    'Fortinet / FortiWeb': {
        'headers': [],
        'cookies': ['.fyi-cookie'],
        'server':  ['fortiweb', 'fortigate'],
    },
    'Barracuda': {
        'headers': ['barra_counter_session'],
        'cookies': ['barra_counter_session', 'bnvr4oq'],
        'server':  ['barracuda'],
    },
    'Azure Front Door / Azure WAF': {
        'headers': ['x-azure-ref', 'x-fd-healthprobe', 'x-ms-request-id'],
        'cookies': [],
        'server':  ['microsoft-azure-application-gateway'],
    },
    'Google Cloud Armor': {
        'headers': ['x-goog-request-id', 'x-gfe-request-class'],
        'cookies': [],
        'server':  ['gws', 'google frontend'],
    },
    'Nginx + Naxsi': {
        'headers': ['x-naxsi-sig'],
        'cookies': [],
        'server':  [],
    },
    'Wallarm': {
        'headers': ['x-wallarm-node-uuid'],
        'cookies': [],
        'server':  [],
    },
    'Alibaba Cloud WAF': {
        'headers': ['ali-cdn-real-ip', 'eagleeye-traceid', 'x-swift-cachetime'],
        'cookies': [],
        'server':  ['tengine'],
    },
}

# 벤더 '고유' 문자열만 둔다 — 'request blocked'·'not acceptable'·'error code: 403'처럼 정상
# 앱도 쓰는 일반 문구를 벤더 리스트에 두면 틀린 벤더명으로 귀속된다('access denied'→Akamai
# 오탐과 같은 계열). block 의도 문구는 GENERIC_BLOCK_KEYWORDS('blocked' 등)가 이미 커버하므로
# 여기서 빼도 탐지는 유지되고(단 'Unknown/Custom WAF'로), 상태코드는 BLOCK_STATUS_CODES가 본다.
BLOCK_PAGE_SIGNATURES = {
    'Cloudflare': [
        'attention required! | cloudflare',
        'cloudflare ray id',
        'error 1010',
    ],
    'AWS WAF': [
        'awswaf',
    ],
    'Akamai': [
        # 'access denied'는 정상 앱도 흔히 쓰는 문구(예: 페이지 JS의 alert('Access denied ...'))라
        # 벤더 특정 시그니처에서 뺀다 — 일반 키워드(GENERIC_BLOCK_KEYWORDS)로만 남겨 baseline
        # 차분/상태코드 corroboration을 받게 한다. 'akamai ghost'·'reference #'는 고유해 유지.
        'akamai ghost', 'reference&#32;&#35;',
    ],
    'Imperva / Incapsula': [
        'incapsula incident id', 'powered by incapsula',
    ],
    'ModSecurity': [
        'mod_security', 'modsecurity',
    ],
    'F5 BIG-IP ASM': [
        'the requested url was rejected',
    ],
    'Sucuri': [
        'access denied - sucuri website firewall', 'sucuri cloudproxy',
    ],
    'Azure Front Door / Azure WAF': [
        'microsoft azure application gateway',
    ],
    'Google Cloud Armor': [
        'your client does not have permission', "that's an error",
    ],
    'Nginx + Naxsi': [
        'naxsi', '&#36;naxsi_fmt',
    ],
    'Alibaba Cloud WAF': [
        'error: 405', 'blocked by alibaba',
    ],
}

GENERIC_BLOCK_KEYWORDS = [
    'blocked', 'forbidden', 'denied', 'rejected',
    'not allowed', 'not acceptable', 'bad request',
    'access denied', 'request denied', 'request rejected',
    'security violation', 'security policy',
    'malicious request', 'suspicious activity',
    'waf', 'firewall', 'web application firewall',
    'bot detected', 'automated request',
    'your ip has been blocked',
    'this request has been blocked',
    # CTF/개인 프로젝트 앱들이 흔히 쓰는 자체 필터 거부 문구. recon의 거부 지문 탐지도
    # 이 테이블을 그대로 공유한다(예전엔 recon._WAF_BODY_SIGNATURES로 따로 들고 있다가
    # "동기화 유지" 부담이 있었으나, validation 통합으로 단일 테이블화했다).
    'hack', 'attack', 'illegal', 'detected',
]

BLOCK_STATUS_CODES      = {403, 406, 444, 503, 999}
RATE_LIMIT_STATUS_CODES = {429}

# recon의 반사/쿼트 프로빙(DBDetect._detect_waf_body)이 쓰는 '거부 본문' 보수적 키워드셋.
# 그 자리는 baseline 없이 절대값으로 보므로(차분 아님) GENERIC_BLOCK_KEYWORDS보다 좁게
# 유지한다 — 'denied'·'forbidden' 같은 흔한 단어까지 넣으면 정상 페이지를 WAF-차단으로
# 오판해 반사 탐지를 통째로 스킵해버린다(native 콘텐츠 오탐). classify_waf_block은 더 넓은
# GENERIC을 쓰되 baseline 차분/상태코드로 거르므로 괜찮다 — 쓰임이 달라 의도적으로 분리.
REFLECTION_BLOCK_KEYWORDS = frozenset([
    'hack', 'blocked', 'attack', 'detected', 'illegal',
    'not allowed', 'bad request', 'security violation', 'waf', 'firewall',
])


def match_block_keywords(body_lower: str, keywords) -> list[str]:
    """차단 키워드를 '단어 경계(\\b...\\b)'로 매칭한 목록을 돌려준다.

    단순 부분 문자열(`kw in body`)로 보면 'hack'이 'hackathon'·'lifehack' 같은 긴 단어나
    브랜드명/로고 텍스트 안에서 걸려 오탐이 난다 — 그런 단어가 모든 페이지에 깔려 있으면
    상시 가짜 WAF가 뜬다. 단어 경계로 보면 'hack'은 단독 단어일 때만 매칭되고 'hackathon'·
    'waffle'(←'waf') 같은 포함어는 안 걸린다. (상태코드 동반 조건은 쓰지 않는다 — 200으로
    'blocked' 본문만 주는 커스텀 WAF를 놓치기 때문.) recon의 거부 지문 탐지도 이 함수 +
    같은 GENERIC_BLOCK_KEYWORDS를 그대로 공유한다(별도 테이블 폐지)."""
    return [kw for kw in keywords
            if re.search(r'\b' + re.escape(kw) + r'\b', body_lower)]


# ── 차단 페이지 판별기 (공용 — SQLiStrategy 등에서도 그대로 재사용) ──────────────

def classify_waf_block(status: int | None, body: str,
                       baseline: str | None = None) -> tuple[bool, str | None, list[str]]:
    """(차단여부, WAF 이름, 근거) — 이 응답이 WAF/앞단 거부인지 판단.

    baseline(정상 응답 본문)을 주면 '차분 게이팅'을 한다: 차단 시그니처/키워드가
    baseline에도 똑같이 들어 있으면 그건 우리 요청에 대한 '반응'이 아니라 그 페이지가
    원래 가진 native 콘텐츠다(예: 안내문·JS 문자열의 'Access denied'). 그런 토큰은
    차단 근거에서 제외한다 — WAF 차단은 정의상 정상과 '달라지는' 반응이기 때문. 이게
    validation 통합의 핵심 원칙(절대값 → baseline 차분)의 최소 구현이다.
    baseline=None이면 예전처럼 본문만 보고 판단한다(baseline을 모르는 per-probe 호출용).
    """
    if status is None or not body:
        return False, None, []
    body_lower = body.lower()
    base_lower = baseline.lower() if baseline else ''

    if status in RATE_LIMIT_STATUS_CODES:
        return True, 'Rate Limit (429)', [f"status_code: {status} (요청 속도 제한, WAF 차단은 아님)"]

    for waf_name, patterns in BLOCK_PAGE_SIGNATURES.items():
        for pattern in patterns:
            # baseline에 이미 있는 시그니처는 그 페이지 native 콘텐츠 → 차단 반응 아님
            if pattern in body_lower and pattern not in base_lower:
                return True, waf_name, [f"block_page_signature: {pattern!r}"]

    matched = match_block_keywords(body_lower, GENERIC_BLOCK_KEYWORDS)
    if base_lower:
        native = set(match_block_keywords(base_lower, GENERIC_BLOCK_KEYWORDS))
        matched = [kw for kw in matched if kw not in native]
    if matched:
        evidence = [f"generic_keywords: {matched[:3]}"]
        if status in BLOCK_STATUS_CODES:
            evidence.append(f"status_code: {status}")
        return True, 'Unknown / Custom WAF', evidence

    return False, None, []


# ── 반응 측정 프리미티브 (baseline 차분) ──────────────────────────────────────────
# validation의 핵심: "입력에 앞단이 어떻게 반응하나"를 baseline과 비교해서 잰다. 필터맵
# (recon, per-surface 오케스트레이션)과 전략의 per-payload 게이트가 이 토큰 vocabulary와
# 반응 분류기를 공유한다 — 필터냐 WAF냐는 이 측정 위에 얹는 해석일 뿐이다.

# 토큰 하나하나를 특정 vuln-type에 매핑해두는 참조 테이블(필터맵 프로브 vocabulary).
# profiler가 필터맵 결과를 hints 점수로 바꿀 때 이 가중치를 쓰는데, 토큰 하나는 자기한테
# 매핑된 vuln-type에만 점수를 주고 다른 유형엔 절대 안 번진다(따옴표 차단이 xss로 번지면
# 안 됨). 빈 매핑({}) = 걸려도 특정 유형을 못 가리키므로 hint엔 기여 안 함(중립 토큰). 특정
# CTF/타겟의 실제 필터 목록을 베끼지 않고, 취약점 유형별 대표 토큰으로 일반화해뒀다.
FILTER_PROBE_TOKENS: dict[str, dict[str, float]] = {
    # ── 중립 (여러 취약점에 공용) ────────────────────────────────────────────
    "'":  {}, '"':  {},                         # 문자열 구분자 (SQLi·XSS 속성 등 공용)
    '$':  {},                                   # 변수/템플릿 마커 (SSTI·JS·PHP)
    ' ':  {}, ',':  {}, '%':  {},               # 공백·구분자·와일드카드
    '-':  {}, '+':  {}, '*':  {}, '/':  {},     # 산술/구조 원자 ('../'·'/*' 귀속에 필요)
    '(':  {}, ')':  {},                         # 함수 호출 구문 (alert()·서브쿼리 등 공용)
    ';':  {}, '|':  {}, '`':  {},               # 문장 구분·파이프·백틱 (CmdI·SQL·JS, cmdi 미구현)

    # ── SQLi ─────────────────────────────────────────────────────────────────
    '--':          {'sqli': 0.4},
    '#':           {'sqli': 0.3},
    '/*':          {'sqli': 0.3},
    'union':       {'sqli': 0.5},
    'select':      {'sqli': 0.5},
    'sleep':       {'sqli': 0.3},
    'order':       {'sqli': 0.5},
    'having':      {'sqli': 0.4},
    'like':        {'sqli': 0.4},
    'substr':      {'sqli': 0.4},
    'substring':   {'sqli': 0.4},
    'ascii':       {'sqli': 0.4},
    'benchmark':   {'sqli': 0.4},
    'database':    {'sqli': 0.5},
    'information_schema': {'sqli': 0.5},
    # 'or'/'and'/'from' — SQL 논리/키워드 원자. 원자라 minimal-token 축소가 'order'/
    # 'information_schema' 등을 이쪽에 귀속하고, sqli.py가 밴을 인지해 ||/&& 치환·공백 제거
    # 우회(symbolic_no_space)를 발동한다.
    'or':          {'sqli': 0.4},
    'and':         {'sqli': 0.4},
    'from':        {'sqli': 0.4},

    # ── XSS ──────────────────────────────────────────────────────────────────
    '<':           {'xss': 0.5},
    '>':           {'xss': 0.3},
    'script':      {'xss': 0.5},
    'onerror':     {'xss': 0.5},
    'javascript:': {'xss': 0.4},
    # 'on' — 이벤트 핸들러 원자. 'onerror'·'union'("uni-on")·'information_schema'가 사실은
    # 'on' 때문에 걸린 것임을 minimal-token 축소가 귀속한다(SQL 쪽 'or' 원자와 같은 역할).
    'on':          {'xss': 0.4},

    # ── SSTI ─────────────────────────────────────────────────────────────────
    '{{':          {'ssti': 0.5},
    '}}':          {'ssti': 0.3},
    '__class__':   {'ssti': 0.5},

    # ── Path traversal ───────────────────────────────────────────────────────
    '../':         {'path_traversal': 0.5},
    '..\\':        {'path_traversal': 0.4},
}


def classify_reflected_reaction(body: str, anchor: str, token: str) -> str:
    """반사형 반응 분류 — 응답에서 anchor(영숫자, 항상 생존) 바로 뒤에 token이 어떻게
    반사됐나로 outcome을 잰다. passed/encoded/removed/rejected.
      - token 그대로         → passed
      - 자리에 HTML 엔티티    → encoded (출력 이스케이프. &lt; &#39; &#x27; 등 어느 형태든
                               &#?\\w+; 패턴으로 봄. 백엔드엔 도달, 출력만 변형 → 필터 아님)
      - 그 외(사라짐/잘림)    → removed (백엔드가 token을 strip)
      - anchor조차 안 돌아옴  → rejected (입력이 '통째로' 거부됨: "filtered!!!" 같은 고정 응답)
    rejected와 removed를 가르는 게 중요하다 — 중첩 우회(토큰 사이에 토큰 끼우기)는 strip형
    (removed)에만 통하고 reject형엔 안 통하기 때문. raw body로 봐야 인코딩·태그 생존을 그대로
    관측한다. (예전 recon._reflected_outcome — validation 통합으로 anchor를 인자로 받게 일반화.)"""
    idx = body.rfind(anchor)
    if idx == -1:
        return 'rejected'
    seg = body[idx + len(anchor):]
    if seg.startswith(token):
        return 'passed'
    if any(not c.isalnum() for c in token) and re.match(r'&#?\w+;', seg):
        return 'encoded'
    return 'removed'


def reduce_substring_bans(outcomes: dict[str, str]) -> dict[str, str]:
    """더 짧은 '걸린' 토큰이 부분 문자열로 든 토큰은 그 짧은 토큰 탓이지 독립 밴이 아니다 —
    앱 필터가 substring 매칭이면(예: '$'가 걸리면 '$where'도 덩달아) 중복/교차유형으로 hints가
    부푼다. 그런 토큰은 passed로 되돌린다. (예전 recon._reduce_substring_bans.)"""
    banned = [t for t, o in outcomes.items() if o != 'passed']
    for t in banned:
        if any(other != t and other in t for other in banned):
            outcomes[t] = 'passed'
    return outcomes


# ── 필터맵 프로버 (토큰별 outcome 측정, baseline 차분) ────────────────────────────
# recon이 이 프로버로 per-surface 필터 지도를 수집한다. 실제 전송은 호출부가
# send_fn(url, method, data) -> (resp, elapsed, err) 콜백으로 주입한다(try_evade와 같은
# 패턴) — "무엇을 보내 어떻게 판정하나"만 여기 두고 전송 방식엔 독립적이다. 결과(outcome
# dict)는 recon이 받아 surface.extra['filter_map']로 흘려보낸다.

_FILTER_MIN_DIFF_FLOOR = 1  # 거부 지문 판정 바닥값. 실제 임계값은 페이지 노이즈로 max(noise*2, floor).


def probe_filter_map(send_fn, url, method, data, target, baseline_body, anchor,
                     noise=0, reflection=None) -> dict[str, str] | None:
    """필터 지도 — 토큰별 outcome('passed'/'removed'/'encoded'/'rejected').

    필터는 두 형태로 드러난다:
      · 반사형: 'anchor+token'을 보내 token이 출력에 생존하는지로 변형을 직접 관측
                (passed/removed/encoded). 몰래 sanitize하는 필터를 잡는다.
      · 응답형: 반사 안 되면 응답이 '거부 페이지'가 되는지로 판정(passed/rejected).
    반환 None = 반응하는 필터 없음. anchor는 영숫자 프로브 마커(recon.BASELINE), noise는
    호출부(recon)가 compare.profile_response로 미리 잰 페이지 노이즈(거부 임계 산정용).
    누적형(memo) 가드는 여기서 안 한다 — recon이 behavior.accumulating으로 사전 게이트한다."""
    if reflection and reflection.get('reflected'):
        return _filter_map_reflective(send_fn, url, method, data, target, anchor)
    normal_text = visible_text(baseline_body or '')
    return _filter_map_rejective(send_fn, url, method, data, target, normal_text, noise, anchor)


def _filter_map_reflective(send_fn, url, method, data, target, anchor) -> dict[str, str] | None:
    """반사형: 'anchor+token'을 보내 token이 출력에 어떻게 반사되는지로 outcome 판정.
    passed(그대로 생존)/encoded(엔티티 변형)/removed(사라짐·잘림)."""
    tokens = list(FILTER_PROBE_TOKENS)
    # 싼 선검사: 전부 이어붙여 한 번에 — 통째로 생존하면 반응하는 필터 없음.
    composite = anchor + ''.join(tokens)
    resp, _, _ = send_fn(url, method, {**data, target: composite})
    if resp is None:
        return None
    if classify_reflected_reaction(resp.text, anchor, ''.join(tokens)) == 'passed':
        return None

    print(f"        필터 감지 — 토큰 {len(tokens)}개 개별 확인 중...", flush=True)
    outcomes: dict[str, str] = {}
    for token in tokens:
        t_resp, _, _ = send_fn(url, method, {**data, target: anchor + token})
        if t_resp is None:
            outcomes[token] = 'removed'
            continue
        # 5xx/SQL 에러 = 토큰이 필터를 통과해 백엔드까지 도달(주입 신호) → 걸린 게 아님.
        if t_resp.status_code >= 500 or detect_db_from_error(t_resp.text):
            outcomes[token] = 'passed'
            continue
        outcomes[token] = classify_reflected_reaction(t_resp.text, anchor, token)
    return reduce_substring_bans(outcomes)


def _filter_map_rejective(send_fn, url, method, data, target,
                          normal_text, noise, anchor) -> dict[str, str] | None:
    """응답형(거부 지문): 반사 안 되는 엔드포인트에서 토큰이 '차단 페이지'를 유발하는지로
    판정한다. 임계값은 페이지 노이즈로 동적으로 잡는다(max(noise*2, floor)). noise는
    호출부(recon)가 compare.profile_response로 미리 측정해 넘겨준다."""
    threshold = max(noise * 2, _FILTER_MIN_DIFF_FLOOR)

    composite = anchor + ''.join(FILTER_PROBE_TOKENS.keys())
    resp, _, _ = send_fn(url, method, {**data, target: composite})
    if resp is None:
        return None

    # 종합 카나리가 500/SQL에러면 거부 지문이 '에러 페이지'로 오염됨 — 따옴표 빼고 재생성.
    if resp.status_code >= 500 or detect_db_from_error(resp.text):
        print(f"    [필터맵] {method} {url} (param={target!r}) — 종합 카나리가 SQL 에러 유발(=주입 신호) — 따옴표 제외하고 거부 지문 재생성")
        composite = anchor + ''.join(t for t in FILTER_PROBE_TOKENS if t not in ("'", '"'))
        resp, _, _ = send_fn(url, method, {**data, target: composite})
        if resp is None:
            return None

    reject_text = visible_text(resp.text)
    if diff_score(normal_text, reject_text) <= threshold:
        return None  # 정상과 노이즈 수준 차이 = 반응하는 필터 없음

    print(f"        필터 감지 — 토큰 {len(FILTER_PROBE_TOKENS)}개 개별 확인 중...", flush=True)
    outcomes: dict[str, str] = {}
    for token in FILTER_PROBE_TOKENS:
        t_resp, _, _ = send_fn(url, method, {**data, target: anchor + token})
        if t_resp is None:
            outcomes[token] = 'passed'
            continue
        if t_resp.status_code >= 500 or detect_db_from_error(t_resp.text):
            outcomes[token] = 'passed'
            continue
        is_reject = diff_score(visible_text(t_resp.text), reject_text) <= threshold
        outcomes[token] = 'rejected' if is_reject else 'passed'
    return reduce_substring_bans(outcomes)


def detect_waf_body(body: str) -> bool:
    """body에 '거부 본문' 키워드가 (단어경계로) 있는지 — recon의 반사/쿼트 프로빙이 baseline
    없이 쓰는 보수적 절대값 체크(REFLECTION_BLOCK_KEYWORDS). 'hack'이 긴 단어에 포함돼 걸리는
    오탐은 match_block_keywords의 단어경계가 막는다."""
    return bool(match_block_keywords(body.lower(), REFLECTION_BLOCK_KEYWORDS))


# ── WAF 우회 변형 ─────────────────────────────────────────────────────────────
# 원본 페이로드가 WAF에 막혔을 때만 재시도하는 변형들. 임의의 페이로드 문자열에
# 적용 가능한 범용 변환 함수라서 quote/boolean/error-time 프로브는 물론, POST 폼
# 퍼징의 후보 파라미터 값에도 그대로 재사용한다.
#
# 주의: 여기서 문자열에 직접 %XX 텍스트를 끼워넣으면 안 된다 — requests의 params=/data=
# 딕셔너리를 그대로 쓰면 전송 시 그 안의 '%' 문자를 다시 인코딩해버려서(%→%25) 결과적으로
# 이중 인코딩이 된다. Flask/Werkzeug 같은 표준 서버는 딱 한 번만 디코딩하므로, 이중
# 인코딩된 값은 실제 SQL로 복원되지 못하고 그냥 이상한 문자열 그대로 앱에 전달된다 —
# WAF는 우회하지만 페이로드 자체가 무력화되는 것. (원래 double_encode/alt_whitespace(%09)
# 변형이 이 버그가 있었음 — 실제 문자(탭 등)를 그대로 쓰고 인코딩은 requests에게 맡기면 안전하다.)

_SQL_KEYWORDS_RE = re.compile(
    r'\b(or|and|select|union|sleep|order|where|from|extractvalue|updatexml|waitfor|delay)\b',
    re.IGNORECASE,
)


def _evade_inline_comment(payload: str) -> str:
    """공백을 /**/로 바꾼다 — MySQL은 공백처럼 처리하지만 '키워드+공백' 패턴 매칭은 깨진다."""
    return payload.replace(' ', '/**/')


def _mix_case(m: re.Match) -> str:
    """매치된 키워드의 대소문자를 교대로 섞는다(대소문자 구분 패턴 매칭 우회). SQL·XSS case-mix가
    공유한다 — 매치 단위라 payload·exec_sig에 각각 적용해도 결과가 일관된다."""
    s = m.group(0)
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))


def _evade_case_mix(payload: str) -> str:
    """SQL 키워드의 대소문자를 섞는다 — 대소문자 구분 패턴 매칭 우회."""
    return _SQL_KEYWORDS_RE.sub(_mix_case, payload)


def _evade_alt_whitespace(payload: str) -> str:
    """공백을 실제 탭 문자로 바꾼다 — requests가 알아서 %09로 정상 인코딩하므로 이중 인코딩 문제가 없다."""
    return payload.replace(' ', '\t')


def _evade_version_comment(payload: str) -> str:
    """MySQL 버전 조건부 주석으로 키워드를 감싼다 — 다른 엔진/WAF엔 그냥 주석이지만 MySQL은 실행한다."""
    return _SQL_KEYWORDS_RE.sub(lambda m: f"/*!50000{m.group(0)}*/", payload)


_OR_WORD_RE  = re.compile(r'\s*\bor\b\s*', re.IGNORECASE)
_AND_WORD_RE = re.compile(r'\s*\band\b\s*', re.IGNORECASE)


def _evade_symbolic_operators(payload: str) -> str:
    """'or'/'and' 키워드 자체를 지운다 — 체크가 항상 소문자로 비교해서 대소문자를 섞어도
    소용없는 WAF 앞에서는, 아예 그 단어를 안 쓰는 것만이 유일한 방법이다. MySQL 기본 모드
    (PIPES_AS_CONCAT 미설정)에서 ||/&&는 그대로 논리 OR/AND로 동작하고, 치환할 때 주변
    공백까지 같이 삼켜서 지우므로 공백 문자 개수 자체도 줄어든다."""
    payload = _OR_WORD_RE.sub('||', payload)
    payload = _AND_WORD_RE.sub('&&', payload)
    return payload


def _evade_strip_safe_whitespace(payload: str) -> str:
    """공백류 문자를 전부(스페이스/탭/개행/CR/수직탭/폼피드) 막는 WAF를 겨냥한다. 무조건
    다 지우면 'AND SLEEP'처럼 양옆이 전부 영문자/숫자인 자리의 공백까지 지워져서
    'ANDSLEEP'라는 다른 토큰으로 합쳐지며 문법이 깨지므로, 괄호/쉼표/따옴표/연산자처럼
    한쪽이라도 단어문자(영문자·숫자·밑줄)가 아닌 자리의 공백만 안전하게 지운다."""
    def repl(m: re.Match) -> str:
        start, end = m.span()
        before = payload[start - 1] if start > 0 else ''
        after  = payload[end] if end < len(payload) else ''
        before_is_word = before.isalnum() or before == '_'
        after_is_word  = after.isalnum() or after == '_'
        return m.group(0) if (before_is_word and after_is_word) else ''
    return re.sub(r'[ \t\r\n\x0b\x0c]+', repl, payload)


def _evade_symbolic_no_space(payload: str) -> str:
    """symbolic_operators + strip_safe_whitespace를 이어 붙인 조합 기법. 공백 전체와
    '-'/'+'/'/', or/and 키워드를 동시에 막는 엄격한 블랙리스트형 WAF는 개별 치환 하나만으론
    안 뚫린다 — OR만 없애도 다른 공백이 그대로 남는 식이라, 두 기법을 한 payload 안에서
    같이 적용해야 실제로 살아남는 문자열이 나온다."""
    return _evade_strip_safe_whitespace(_evade_symbolic_operators(payload))


_LIMIT_CLAUSE_RE = re.compile(r'\s*\blimit\s+\d+\s*', re.IGNORECASE)


def _evade_blind_no_limit(payload: str) -> str:
    """blind 오라클 payload(f"OR (조건) LIMIT n {comment}")의 'LIMIT n' 부분을 통째로
    지운다 — LIMIT과 숫자 사이 공백은 양쪽 다 단어문자라 strip_safe_whitespace로도 못
    지우는 유일한 잔여 공백이라, 다른 치환을 다 적용해도 이 자리 하나 때문에 계속 막힌다.
    페이로드 생성부(_bool_oracle 등) 자체는 그대로 두고 — LIMIT이 응답 크기를 제한하는
    용도로는 여전히 유효하니 기본값으로는 유지하되, 이 payload가 막혔을 때만 최후 수단으로
    LIMIT을 빼고(+ symbolic_operators까지 같이 적용해서) 재시도하는 우회 기법으로 둔다."""
    payload = _evade_symbolic_operators(payload)
    payload = _LIMIT_CLAUSE_RE.sub(' ', payload)
    return _evade_strip_safe_whitespace(payload)


_SUBSTR_NAME_RE = re.compile(r'\b(SUBSTR|SUBSTRING)\s*\(', re.IGNORECASE)


def _split_top_level_args(s: str) -> list[str]:
    """괄호 깊이를 세면서 depth==0인 콤마에서만 자른다 — database()처럼 인자 안에
    또 괄호가 있는 경우(SUBSTR(database(),1,1))도 안 깨지게 하기 위함."""
    parts, depth, last = [], 0, 0
    for i, ch in enumerate(s):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            parts.append(s[last:i])
            last = i + 1
    parts.append(s[last:])
    return parts


def _evade_substr_no_comma(payload: str) -> str:
    """SUBSTR(x,y,z)/SUBSTRING(x,y,z)의 콤마를 ANSI SQL의 FROM/FOR 문법으로 바꾼다 —
    MySQL/PostgreSQL이 지원하는 문법 설탕이라 콤마 자체를 막는 필터를 뚫을 수 있다.
    SQLite는 이 FROM/FOR 문법을 지원하지 않아(콤마 형태만 받음) 여기 적용하면 오히려
    문법 에러가 나므로, try_evade()가 dialect가 MySQL/PostgreSQL일 때만 이 항목을
    시도하도록 걸러준다. payload에 SUBSTR/SUBSTRING 호출이 없으면 그냥 원문 그대로
    돌려줘서(다른 payload엔 적용할 게 없다는 뜻) 상위 루프가 스킵하게 한다.

    단순 정규식으로는 첫 인자가 database()처럼 그 자체로 괄호를 포함하는 함수 호출일 때
    못 뚫는다 — 괄호 깊이를 직접 세서 SUBSTR(...)의 진짜 닫는 괄호를 찾는다."""
    out, i, changed = [], 0, False
    while True:
        m = _SUBSTR_NAME_RE.search(payload, i)
        if not m:
            out.append(payload[i:])
            break
        out.append(payload[i:m.start()])
        fn_name = m.group(1)
        depth, j = 1, m.end()
        args_start = j
        while j < len(payload) and depth > 0:
            if payload[j] == '(':
                depth += 1
            elif payload[j] == ')':
                depth -= 1
            j += 1
        if depth != 0:
            out.append(payload[m.start():j])  # 안 닫힘 — 그냥 원문 유지
            i = j
            continue
        args = _split_top_level_args(payload[args_start:j - 1])
        if len(args) == 3:
            x, pos, length = (a.strip() for a in args)
            out.append(f"{fn_name}({x} FROM {pos} FOR {length})")
            changed = True
        else:
            out.append(payload[m.start():j])
        i = j
    return ''.join(out) if changed else payload


EVASION_TRANSFORMS = [
    ('inline_comment',    _evade_inline_comment),
    ('alt_whitespace',    _evade_alt_whitespace),
    ('version_comment',   _evade_version_comment),
    ('symbolic_no_space', _evade_symbolic_no_space),
    ('blind_no_limit',    _evade_blind_no_limit),
    # case_mix: 대소문자 구분 없이 정규화(.lower() 등) 후 검사하는 필터가 흔해서 실패율이
    # 높다 — 그래도 정말 대소문자 그대로만 비교하는 허술한 필터엔 유일한 우회 수단이라
    # 제거하진 않되, 순서를 뒤로 미뤄서 흔한 실패 케이스의 낭비 요청을 줄인다.
    ('case_mix',          _evade_case_mix),
    # substr_no_comma: SQLite에선 문법 에러만 나서(FROM/FOR 미지원) MySQL/PostgreSQL일
    # 때만 시도해야 한다 — try_evade()가 dialect 인자로 걸러준다.
    ('substr_no_comma',   _evade_substr_no_comma),
]

_DIALECT_ONLY_TRANSFORMS = {'substr_no_comma': ('MySQL', 'PostgreSQL')}


# ── XSS 전용 우회 변형 (SQL과 같은 구조, 다만 HTML/JS 문맥에 안전한 것만) ────────────
# SQL의 _evade_case_mix는 SQL 키워드만 섞고, inline_comment(/**/) 등은 HTML을 깨뜨린다.
# XSS는 HTML 태그/이벤트 핸들러 이름만 대소문자를 섞어야 한다 — JS(alert)와 마커는 대소문자
# 민감/식별자라 건드리면 실행·귀속이 깨진다. alt_whitespace(공백→탭)는 HTML 속성 구분자로
# 유효해 그대로 재사용한다. (대체 벡터 다양화는 범위 밖 — 변형만.)
_XSS_KEYWORDS_RE = re.compile(
    r'\b(on\w+|script|img|svg|iframe|body|details|video|audio|autofocus)\b',
    re.IGNORECASE,
)


def _evade_xss_case(payload: str) -> str:
    """HTML 태그/이벤트 핸들러 키워드만 대소문자를 섞는다. HTML은 태그·속성명이 대소문자
    무관이라 실행은 보존되고, 대소문자 그대로 비교/치환하는 필터(예: lower()로 검사 후 원문의
    소문자만 치환)는 깨진다. JS·마커는 키워드 집합 밖이라 안 건드린다. 매치 단위로 결정적이라
    payload와 exec_sig에 각각 적용해도 같은 결과가 나온다(생존 판정에 필요)."""
    return _XSS_KEYWORDS_RE.sub(_mix_case, payload)


def _evade_paren_to_backtick(payload: str) -> str:
    """fn('arg')/fn(arg) → fn`arg` (태그드 템플릿 = 괄호 없는 호출). '(' ')'를 막는 필터 우회용.
    템플릿 리터럴은 인자를 문자열로 넘기므로 alert('M')처럼 단일 문자열/숫자 호출에 맞다 —
    따옴표가 있으면 벗기고 백틱으로 감싼다. payload와 exec_sig에 똑같이 적용돼 일관된다
    (예: alert('fbsxm..') → alert`fbsxm..` — alert 메시지는 마커 그대로라 dialog 매칭도 OK)."""
    return re.sub(r"(\w+)\((['\"]?)([^()'\"]*)\2\)", r"\1`\3`", payload)


_URL_SCHEME_RE = re.compile(r'(?i)(java)(scr)(ipt)')


def _evade_url_scheme_sep(payload: str) -> str:
    """URL 실행 스킴 'javascript' 안(script 내부)에 탭을 끼운다 → 'javascr\\tipt'. 'javascript:'는
    URL 자리에서 JS를 직접 실행하는 스킴인데(iframe src·a href·form action 등), 서버의 substring
    필터는 탭 때문에 'javascript'·'script'를 못 찾고, 브라우저는 URL 파싱 때 탭/개행(0x09/0A/0D)을
    제거해 'javascript:'로 재구성한다. 스킴 대상이라 벡터(iframe/a/form) 무관하게 공용. 매치 단위
    결정적이라 payload·exec_sig에 각각 적용해도 일관된다. (지금은 javascript만 — data:/vbscript는 후속.)"""
    return _URL_SCHEME_RE.sub('\\1\\2\t\\3', payload)


XSS_EVASION_TRANSFORMS = [
    ('xss_case',          _evade_xss_case),
    ('alt_whitespace',    _evade_alt_whitespace),
    ('paren_to_backtick', _evade_paren_to_backtick),
    ('url_scheme_sep',    _evade_url_scheme_sep),
    ('xss_case+ws',       lambda p: _evade_alt_whitespace(_evade_xss_case(p))),
    ('xss_case+backtick', lambda p: _evade_paren_to_backtick(_evade_xss_case(p))),
    # 'javascript'·'script'·'(' 를 동시에 막는 필터용 — 스킴 탭 분리 + 괄호→백틱
    # (<iframe src=javascript:alert('M')> → <iframe src=javascr\tipt:alert`M`>)
    ('urlsep+backtick',   lambda p: _evade_paren_to_backtick(_evade_url_scheme_sep(p))),
]


def apply_named_evasion(name: str, payload: str) -> str:
    """캐시에 저장된 기법 이름으로 실제 변환을 재적용한다. 단일 기법 이름('inline_comment')
    이든, try_evade가 최후 수단으로 찾아낸 조합 이름('inline_comment+case_mix', a→b 순서로
    적용)이든 이 함수 하나로 통일해서 처리한다 — 호출부(SQLiStrategy의 캐시 fast-path)가
    조합/단일을 구분할 필요 없이 그대로 쓸 수 있게 하기 위함."""
    transforms = dict(EVASION_TRANSFORMS)
    result = payload
    for part in name.split('+'):
        fn = transforms.get(part)
        if fn is None:
            return payload  # 알 수 없는 이름 — 안전하게 원문 그대로
        result = fn(result)
    return result


def _try_evade_pairs(send_fn, payload: str, dialect: str | None, skip: set[str], is_banned=None):
    """단일 기법이 전부 실패했을 때 최후 수단으로 2개씩 조합해서 재시도한다.

    'a 다음에 b'와 'b 다음에 a'는 결과가 다를 수 있어서(예: 공백을 지운 뒤 키워드를
    바꾸는 것과 그 반대는 매칭 대상 문자열이 다르다) 순서 있는 쌍을 전부 본다 — 등록
    기법이 7개면 7×6=42가지. 다만 a가 이 payload에 적용할 게 없으면(no-op) 그 a로
    시작하는 조합은 전부 단일 b와 결과가 똑같아서 스킵하고, b가 a 적용 결과에 추가로
    바꿀 게 없어도 마찬가지로 스킵한다 — 이러면 단일 단계에서 이미 실패가 확인된 것과
    동일한 조합을 다시 보내는 낭비가 없다.

    성공하면 (status, body, elapsed, variant, 'a+b') 튜플을, 전부 실패하면 None을 반환한다.
    """
    available = [
        (name, fn) for name, fn in EVASION_TRANSFORMS
        if name not in skip
        and not (_DIALECT_ONLY_TRANSFORMS.get(name) and dialect not in _DIALECT_ONLY_TRANSFORMS[name])
    ]
    for name_a, fn_a in available:
        variant_a = fn_a(payload)
        if variant_a == payload:
            continue
        for name_b, fn_b in available:
            if name_b == name_a:
                continue
            variant_ab = fn_b(variant_a)
            if variant_ab == variant_a:
                continue
            if is_banned and is_banned(variant_ab):
                continue  # 우회가 밴 토큰을 재도입 — WAF는 뚫어도 벤 필터에 다시 걸려 무의미
            status, body, elapsed = send_fn(variant_ab)
            if status is None:
                continue
            blocked, _, _ = classify_waf_block(status, body)
            if not blocked:
                return status, body, elapsed, variant_ab, f'{name_a}+{name_b}'
    return None


def try_evade(send_fn, payload: str, label: str, waf_hits: list, waf_evasions: list,
              dialect: str | None = None, skip: set[str] | None = None, quiet: bool = False,
              is_banned=None):
    """payload가 WAF에 막혔을 때 우회 변형들을 순서대로 재시도하는 공용 로직.

    skip(호출부의 필드별 캐시가 이미 시도해서 실패한 기법 이름들)에 든 항목은 건너뛴다 —
    안 그러면 캐시된 기법이 실패했을 때 여기서 처음부터 다시 돌면서 그 기법을 한 번 더
    중복 시도하게 된다.

    send_fn(variant) -> (status, body, elapsed) 형태의 콜러블을 받는다 — 실제 전송
    방식(requests.Session 동기 호출인지, Scrapy 콜백 체인의 한 스텝인지)은 호출부가
    알아서 하고, 여기는 "어떤 변형을 시도하고 어떻게 판정하는지"만 책임진다.
    성공하면 (status, body, elapsed, 실제로 먹힌 payload, 기법 이름) 튜플을, 전부
    실패하면 None을 반환한다. 성공한 첫 변형에서 즉시 멈춘다 — 여러 개가 통해도 하나면
    충분. 기법 이름을 같이 돌려주는 건 호출부(SQLiStrategy)가 같은 필드에 재사용할 수
    있게 캐싱하기 위함이다.

    (예전엔 double_url_encode라는 기법도 있었는데, '필터 통과'가 '진짜 그 문자가
    DB까지 전달됨'을 보장하지 않아서 — 단일 디코딩 서버(Flask 등)에선 인코딩된 문자열
    그대로 남는데도 "우회 성공"으로 보고됐다. 특히 _bool_oracle 같은 참/거짓 판정
    로직에서는 이 가짜 성공이 무작위 응답을 실제 신호처럼 오인시켜 존재하지도 않는
    데이터를 "추출"해버릴 위험이 있어서 완전히 제거했다.)

    dialect(SQLite/MySQL/PostgreSQL 등, 모르면 None)가 _DIALECT_ONLY_TRANSFORMS에 등록된
    기법(현재 substr_no_comma)의 허용 목록에 없으면 그 기법은 건너뛴다 — SQLite에 FROM/FOR
    문법을 시도하면 필터는 통과해도 SQL 문법 자체가 깨져서 오탐/낭비 요청만 생긴다.

    단일 기법 7개가 전부 실패하면 마지막 수단으로 2개 조합(_try_evade_pairs)을 시도한다 —
    공백/키워드/따옴표를 각각 따로 막는 게 아니라 여러 조건을 동시에 거는 WAF는 단일
    기법 하나로는 안 뚫리고 두 변형을 겹쳐야만 통과하는 경우가 있다.
    """
    skip = skip or set()
    for name, transform in EVASION_TRANSFORMS:
        if name in skip:
            continue
        allowed_dialects = _DIALECT_ONLY_TRANSFORMS.get(name)
        if allowed_dialects and dialect not in allowed_dialects:
            continue
        variant = transform(payload)
        if variant == payload:
            continue  # 이 페이로드엔 적용할 게 없음 (예: 공백 없는 홑따옴표 하나)
        if is_banned and is_banned(variant):
            continue  # 우회가 밴 토큰을 재도입 — WAF는 뚫어도 벤 필터에 다시 걸려 무의미
        status, body, elapsed = send_fn(variant)
        if status is None:
            continue
        blocked, _, _ = classify_waf_block(status, body)
        if not blocked:
            if not quiet:
                print(f"    [Evade] {label}: {name} 우회 성공")
            waf_evasions.append(f"{label}: {name} 우회 성공 → \"{variant}\"")
            return status, body, elapsed, variant, name

    combo = _try_evade_pairs(send_fn, payload, dialect, skip, is_banned)
    if combo is not None:
        status, body, elapsed, variant, combo_name = combo
        if not quiet:
            print(f"    [Evade] {label}: {combo_name} 조합 우회 성공")
        waf_evasions.append(f"{label}: {combo_name} 조합 우회 성공 → \"{variant}\"")
        return status, body, elapsed, variant, combo_name

    if not quiet:
        print(f"    [Evade] {label}: 우회 {len(EVASION_TRANSFORMS)}종 + 조합 전부 실패")
    waf_hits.append(f"{label}(\"{payload}\") → 우회 {len(EVASION_TRANSFORMS)}종 + 조합 전부 실패")
    return None


def _run_passive(response_headers: dict, cookies: list) -> list[dict]:
    """헤더/쿠키/Server 문자열로 벤더를 특정한다 (요청 없이 즉시 판단)."""
    results = []
    header_keys = set(k.lower() for k in (response_headers or {}).keys())

    server_values = response_headers.get('Server', response_headers.get('server', [])) if response_headers else []
    if isinstance(server_values, str):
        server_values = [server_values]
    server_str = ' '.join(str(v) for v in (server_values or [])).lower()

    cookie_names = [c.get('name', '').lower() for c in (cookies or []) if isinstance(c, dict)]

    for waf_name, sigs in KNOWN_WAF_SIGNATURES.items():
        evidence = []
        for sig_header in sigs.get('headers', []):
            if sig_header.lower() in header_keys:
                evidence.append(f"header: {sig_header}")
        for sig_cookie in sigs.get('cookies', []):
            for cn in cookie_names:
                if cn.startswith(sig_cookie.lower()):
                    evidence.append(f"cookie: {cn}")
                    break
        for sig_server in sigs.get('server', []):
            if sig_server in server_str:
                evidence.append(f"server: {server_str}")
        if evidence:
            results.append({'waf_name': waf_name, 'evidence': evidence})
    return results


class WafDetector:
    """페이지마다 passive(헤더/쿠키, 요청 없음) + baseline 본문 1회 확인만 수행한다."""

    TIMEOUT = 10

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def run(self, pages: list[dict]) -> None:
        print(f"\n# [WAF 탐지] {len(pages)}개 페이지 확인")
        for page in pages:
            url = page.get('url')
            if not url:
                continue

            passive = _run_passive(page.get('response_headers') or {}, page.get('cookies') or [])
            baseline = page.get('_baseline')
            if baseline is not None:
                status, body = baseline.get('status'), baseline.get('body') or ''
            else:
                status, body = self._fetch(url)
            active_blocked, active_name, active_evidence = classify_waf_block(status, body)
            # baseline은 양성(benign) 요청이라, 정상(차단 코드 아님) 응답은 정의상 차단 페이지가
            # 아니다 — 본문에 'denied' 같은 문구가 있어도 그 페이지 native 콘텐츠일 뿐이다. 여기선
            # 비교할 두 번째 응답이 없어(단일 fetch) diff를 못 재므로, '양성 요청이 차단/레이트리밋
            # 상태코드로 돌아왔을 때'만 본문 기반 판정을 신뢰한다. (공격 응답의 200 커스텀 WAF는
            # 전략 단계에서 baseline 차분으로 따로 잡는다.)
            if active_blocked and status not in BLOCK_STATUS_CODES and status not in RATE_LIMIT_STATUS_CODES:
                active_blocked = False

            if passive:
                waf_info = {
                    'detected': True,
                    'name':     passive[0]['waf_name'],
                    'evidence': passive[0]['evidence'],
                    'source':   'passive',
                }
            elif active_blocked:
                waf_info = {
                    'detected': True,
                    'name':     active_name,
                    'evidence': active_evidence,
                    'source':   'active-baseline',
                }
            else:
                waf_info = {'detected': False, 'name': None, 'evidence': [], 'source': None}

            page['waf_info'] = waf_info
            if waf_info['detected']:
                print(f"  ⚠ WAF 탐지: {url} | {waf_info['name']} ({waf_info['source']}) | {waf_info['evidence']}")
            else:
                print(f"  OK       {url} | WAF 미탐지")

    def _fetch(self, url: str) -> tuple[int | None, str]:
        try:
            resp = self.session.get(url, timeout=self.TIMEOUT)
            return resp.status_code, resp.text
        except Exception:
            return None, ''
