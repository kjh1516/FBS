import re

from fbs.inference.models import AttackSurface
from fbs.inference.validation import FILTER_PROBE_TOKENS

# ── 필드명 가중치 테이블 ──────────────────────────────────────────────────────
# 키: 필드명에 포함된 부분 문자열 (소문자). 단 길이가 _SHORT_KEYWORD_MAXLEN 이하인
# 키워드는 부분 문자열이 아니라 토큰 완전 일치로 매칭한다(아래 _field_hints 참고).
# 값: {취약점 유형: 가중치 0.0~1.0}
#
# 가중치는 "필드명만으로 추정한 확신도"라 상한을 0.8로 잡았다(0.9~0.95는 필드명
# 하나로 내기엔 과한 확신) — username/password처럼 거의 확실한 것만 0.7~0.8대,
# id/no/num/q/pid/idx처럼 짧고 애매한 것은 0.2~0.3대로 낮춰뒀다.

_FIELD_HINTS: dict[str, dict[str, float]] = {
    # 인증 관련 → SQLi 높음
    'username':  {'sqli': 0.8, 'xss': 0.4},
    'userid':    {'sqli': 0.6},
    'password':  {'sqli': 0.8},
    'passwd':    {'sqli': 0.8},
    'pw':        {'sqli': 0.6},
    'pwd':       {'sqli': 0.6},
    'email':     {'sqli': 0.6, 'xss': 0.4},
    'login':     {'sqli': 0.7, 'xss': 0.3},
    'register':  {'sqli': 0.6, 'xss': 0.3},
    'account':   {'sqli': 0.6},
    'member':    {'sqli': 0.5},
    'mid':       {'sqli': 0.3},
    'phone':     {'sqli': 0.4},
    'code':      {'sqli': 0.3},

    # 검색/출력 → XSS·SQLi·SSTI
    'search':    {'sqli': 0.6, 'xss': 0.8, 'ssti': 0.4},
    'query':     {'sqli': 0.6, 'xss': 0.8, 'ssti': 0.4},
    'keyword':   {'sqli': 0.5, 'xss': 0.7},
    'q':         {'sqli': 0.3, 'xss': 0.4},

    # 식별자 → SQLi
    'id':        {'sqli': 0.5},
    'uid':       {'sqli': 0.5},
    'pid':       {'sqli': 0.3},
    'idx':       {'sqli': 0.3},
    'num':       {'sqli': 0.3},
    'no':        {'sqli': 0.3},

    # 출력 콘텐츠 → SSTI·XSS
    'template':  {'ssti': 0.8, 'xss': 0.5},
    'tpl':       {'ssti': 0.7, 'xss': 0.4},
    'content':   {'ssti': 0.6, 'xss': 0.7},
    'body':      {'ssti': 0.6, 'xss': 0.7},
    'message':   {'ssti': 0.5, 'xss': 0.7},
    'text':      {'ssti': 0.4, 'xss': 0.6},
    'comment':   {'ssti': 0.4, 'xss': 0.7},
    'desc':      {'xss': 0.5, 'ssti': 0.3},
    'nickname':  {'sqli': 0.4, 'xss': 0.5},
    'subject':   {'xss': 0.5},
    'review':    {'xss': 0.5, 'ssti': 0.3},
    'name':      {'sqli': 0.3, 'xss': 0.5},
    'title':     {'sqli': 0.3, 'xss': 0.5},

    # 리다이렉트
    'redirect':  {'open_redirect': 0.8},
    'next':      {'open_redirect': 0.7},
    'return':    {'open_redirect': 0.7},
    'goto':      {'open_redirect': 0.8},
    'url':       {'open_redirect': 0.6, 'ssrf': 0.6},
    'path':      {'open_redirect': 0.4, 'ssrf': 0.5, 'path_traversal': 0.6},
    'target':    {'open_redirect': 0.5},

    # 파일
    'file':      {'path_traversal': 0.7},
    'filename':  {'path_traversal': 0.8},
    'filepath':  {'path_traversal': 0.8},
    'upload':    {'path_traversal': 0.6},
    'dir':       {'path_traversal': 0.6},
    'folder':    {'path_traversal': 0.6},

    # SSRF
    'callback':  {'ssrf': 0.6},
    'webhook':   {'ssrf': 0.7},
    'proxy':     {'ssrf': 0.6},

    # NoSQLi
    'filter':    {'nosqli': 0.6, 'sqli': 0.4},
    'where':     {'nosqli': 0.6, 'sqli': 0.6},
    'sort':      {'nosqli': 0.5},
    'order':     {'sqli': 0.5, 'nosqli': 0.4},
}

# 건너뛸 필드 (보안 토큰 등 — 수정하면 요청 자체가 실패)
_SKIP_FIELDS: frozenset[str] = frozenset([
    'csrf', 'csrftoken', 'csrf_token', '_token', 'authenticity_token',
    'captcha', 'recaptcha', '__requestverificationtoken',
])

# tech_stack → 취약점 유형 추가 가중치
_TECH_BOOST: dict[str, dict[str, float]] = {
    'Flask':      {'ssti': 0.3},
    'Django':     {'ssti': 0.2, 'sqli': 0.2},
    'Jinja2':     {'ssti': 0.4},
    'PHP':        {'sqli': 0.2, 'xss': 0.2},
    'Laravel':    {'sqli': 0.2},
    'Rails':      {'sqli': 0.2, 'ssti': 0.2},
    'Express':    {'nosqli': 0.2, 'xss': 0.2},
    'Spring':     {'sqli': 0.2},
    'ASP.NET':    {'sqli': 0.2},
    'MongoDB':    {'nosqli': 0.3},
}

# recon의 전역 필터 차단 비율(__block_ratio__)이 이 값 미만이면 '선택적 차단'(타겟 필터
# 추정, sqli 신호로 취급)으로, 이상이면 '균일 차단'(범용 WAF 추정, 신호 불명확 — 점수를
# 깎지 않고 필드명 기반 베이스라인을 그대로 유지)으로 판단한다.
_SELECTIVE_BLOCK_THRESHOLD = 0.5


# 부분 문자열로 매칭하면 흔한 영단어에 잘못 걸리는 키워드들 — 이것만 토큰 완전 일치로
# 좁힌다(길이 기준이 아니라 실제 오탐 사례 기준). 'id'→valid/avoid/liquid/paid/guid,
# 'no'→annotation/ignore/technology, 'q'→quantity/require/frequency, 'pid'→rapid/stupid/
# cupid, 'uid'→liquid/squid, 'num'→enumerate. 'pw'/'pwd'/'dir'/'idx'/'mid' 등은 이런 식의
# 흔한 오탐 사례가 없어서 부분 문자열 매칭을 그대로 둔다 — 'upw'처럼 구분자 없는 복합
# 표기에서도 'pw'가 부분 문자열로 잡혀야 하기 때문.
_AMBIGUOUS_KEYWORDS: frozenset[str] = frozenset(['id', 'no', 'q', 'pid', 'uid', 'num'])


def _tokenize(field_name: str) -> list[str]:
    """필드명을 '_'/'-'/camelCase 경계로 토큰화한다 — 짧은 키워드의 단어 경계 매칭에 쓴다."""
    spaced = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', field_name)
    return [t for t in re.split(r'[-_]', spaced.lower()) if t]


def _field_hints(field_name: str) -> tuple[dict[str, float], list[tuple[str, str, float]]]:
    """필드명에서 취약점 유형별 가중치를 계산한다.

    반환: (취약점별 최종 가중치, [(매칭된 키워드, 취약점, 가중치), ...] 매칭 근거)
    """
    name_lower = field_name.lower().replace('-', '').replace('_', '')
    tokens = _tokenize(field_name)
    merged: dict[str, float] = {}
    matches: list[tuple[str, str, float]] = []
    for keyword, hints in _FIELD_HINTS.items():
        kw = keyword.replace('_', '')
        matched = (kw in tokens) if kw in _AMBIGUOUS_KEYWORDS else (kw in name_lower)
        if matched:
            for vuln, weight in hints.items():
                merged[vuln] = max(merged.get(vuln, 0.0), weight)
                matches.append((keyword, vuln, weight))
    return merged, matches


def _tech_boost(tech_stack: dict) -> tuple[dict[str, float], list[tuple[str, str, str, float]]]:
    """tech_stack 기반 추가 가중치를 계산한다.

    반환: (취약점별 가중치, [(tech_stack 필드, 값, 취약점, 가중치), ...] 매칭 근거)
    """
    boost: dict[str, float] = {}
    matches: list[tuple[str, str, str, float]] = []
    for field in ('framework', 'language', 'cms', 'server'):
        tech = tech_stack.get(field)
        if tech and tech in _TECH_BOOST:
            for vuln, w in _TECH_BOOST[tech].items():
                boost[vuln] = max(boost.get(vuln, 0.0), w)
                matches.append((field, tech, vuln, w))
    return boost, matches


def _collect_group_hints(page: dict) -> dict[tuple, dict[str, float]]:
    """(url, method)로 묶이는, 같은 요청에 같이 실려가는 필드들끼리 필드명 매칭 점수의
    최댓값을 모아둔다. 형제 필드 중 하나(예: uid→sqli 0.8)가 이름으로 강한 신호를 받았으면,
    자기 이름만으로는 아무 매칭도 안 되는 필드(예: level, upw)도 "같은 쿼리에 같이 들어간다"는
    사실만으로 그 신호를 나눠 받는다 — 실제로 uid/upw/level이 한 SQL문에 같이 쓰이는데
    필드명 사전에 upw/level이 없다는 이유만으로 sqli 신호가 0이 되는 문제를 막기 위함이다.

    hidden_post_params는 scanner.py의 퍼징이 특정 폼을 대상으로 수행돼서 entry['action']이
    그 폼의 action과 문자열 그대로 동일하다 — 그래서 별도 매칭 없이 같은 그룹 키로 자동으로
    묶인다.

    tech_boost(페이지 전체에 균일하게 붙는 배경값)는 여기 안 섞는다 — 필드 고유 신호가
    아니라서, 같이 넣으면 진짜 무신호 필드와 형제 신호가 있는 필드가 구분이 안 된다."""
    groups: dict[tuple, dict[str, float]] = {}

    def _feed(key: tuple, param: str) -> None:
        field_hints, _ = _field_hints(param)
        bucket = groups.setdefault(key, {})
        for vuln, w in field_hints.items():
            bucket[vuln] = max(bucket.get(vuln, 0.0), w)

    base_url = page['url'].split('?')[0]
    for param in (page.get('params') or {}):
        _feed((base_url, 'GET'), param)
    for form in (page.get('forms') or []):
        key = (form.get('action') or page['url'], form.get('method', 'GET').upper())
        for inp in form.get('inputs', []):
            if inp.get('name'):
                _feed(key, inp['name'])
    for param in (page.get('hidden_params') or []):
        _feed((base_url, 'GET'), param)
    for entry in (page.get('hidden_post_params') or []):
        if entry.get('param'):
            _feed((entry.get('action') or base_url, 'POST'), entry['param'])

    return groups


def _with_group_hints(field_hints: dict, group: dict) -> dict[str, float]:
    """자기 필드명 매칭 점수와 같은 그룹(형제 필드들) 매칭 점수 중 최댓값을 취한다."""
    return {
        vuln: max(field_hints.get(vuln, 0.0), group.get(vuln, 0.0))
        for vuln in set(field_hints) | set(group)
    }


def _group_hint_note(own: dict, merged: dict) -> str | None:
    """merged가 own보다 높아진 유형이 있으면(형제 신호를 상속받았으면) 사람이 읽을 근거를 만든다."""
    boosted = {v: w for v, w in merged.items() if w > own.get(v, 0.0)}
    if not boosted:
        return None
    return '형제 필드 신호 상속: ' + ', '.join(f'{v}+{w}' for v, w in boosted.items())


# ── 점수 프레임: 증거 클래스 + prior ──────────────────────────────────────────
# 힌트는 "어느 전략을 먼저 돌릴지"를 고르는 순위용이다(틀려도 fallback이 복구). 그래서
# 점수를 가산으로 뭉개지 않고, 의미가 고정된 '증거 클래스'(큰 간격)로 배정하고 prior(이름/
# 스택)는 밴드 안에서 동점처리로만 얹는다. 규칙:
#   - 클래스 간 간격 > prior 폭  → 측정된 증거가 이름 추측을 '항상' 이긴다.
#   - prior만 있으면 PRIOR 밴드(≤0.39)에 머문다 — 이름만으론 증거 밴드에 못 들어간다.
#   - 0.70 = "입력이 인터프리터에 도달한 걸 측정으로 확인" — SQLi·XSS 공통 의미라 비교 가능.
# 세부 신호→클래스 배정은 문제를 풀며 계속 붙인다(지금은 지배적 신호만 연결).
_CLS_CONFIRMED  = 0.90   # 측정이 주입/실행을 입증 (예: SQL 에러 시그니처)
_CLS_REACHED    = 0.70   # 입력이 인터프리터에 도달 (따옴표로 쿼리 깨짐 / 실행가능 반사)
_CLS_SUGGESTIVE = 0.40   # 정황 증거 (선택적 필터 차단, 토큰 차단, escape된 실행 컨텍스트)
_PRIOR_CEIL     = 0.39   # prior(이름/스택) 단독 상한 — 증거 밴드엔 못 들어감
_PRIOR_TIE      = 0.09   # 증거가 있을 때 prior 기여(밴드 내 동점처리용)


def _banded(evidence_base: float | None, prior: float) -> float:
    """증거 클래스 base가 있으면 그 밴드 + prior를 소수점 동점처리로, 없으면 prior만(≤0.39)."""
    p = max(0.0, min(prior, 1.0))
    if evidence_base is None:
        return round(p * _PRIOR_CEIL, 3)
    return round(evidence_base + p * _PRIOR_TIE, 3)


def _sqli_evidence(db: dict, block_ratio: float) -> tuple[float | None, str | None]:
    """recon 신호 → SQLi 증거 클래스. (base, note) 또는 (None, None).

    상위 밴드는 'SQL 에러 시그니처'(detected_db)만이다 — 응답에서 실제 SQL 에러 패턴을 매칭한
    것이라 SQL-특정적. 반면 '따옴표가 500/상태변화를 유발'은 그 자체로는 SQL 특정이 아니다:
    잘 짠 앱은 SQLi여도 예외처리로 500을 안 내고, 백엔드 로직이 커지면 SQL과 무관한 앱 예외로도
    500이 난다. 그래서 시그니처 없는 따옴표 반응은 '도달 입증(REACHED)'이 아니라 '정황
    (SUGGESTIVE)'으로 둔다 — 실제 확정은 strategy의 boolean/union이 한다.
    (추후 recon이 boolean 차분(probe≈다른 known 응답)을 따로 노출하면 그건 REACHED로 올릴
    여지가 있다 — 지금은 sqli_signal에 섞여 있어 구분 못 함.)"""
    if db.get('detected_db'):
        return _CLS_CONFIRMED, f"SQL 에러 시그니처로 DB({db['detected_db']}) 확인 — 사실상 주입 확정"
    # 시그니처 없는 따옴표/probe 반응 — 단순 반응이라 정황(500은 앱 예외일 수도)
    if db.get('sqli_signal'):
        q = db.get('quote_char')
        why = f"따옴표({q}) 반응" if q else "probe 반응"
        return _CLS_SUGGESTIVE, f"{why} — SQL 에러 시그니처 없음(단순 반응이라 정황)"
    # 선택적 필터 차단 = 개발자가 이 필드를 SQL로 인지하고 막았다 → 정황
    if db.get('waf_blocked') and block_ratio < _SELECTIVE_BLOCK_THRESHOLD:
        return _CLS_SUGGESTIVE, f"선택적 필터 차단(전역 {block_ratio:.0%})"
    return None, None


def _xss_evidence(db: dict) -> tuple[float | None, str | None]:
    """recon 반사 신호 → XSS 증거 클래스. (base, note) 또는 (None, None)."""
    refl = db.get('reflection')
    if not refl:
        return None, None
    if refl.get('reflected'):
        ctxs     = set(refl.get('contexts') or [])
        survived = set(refl.get('survived') or [])
        exec_ctx = ctxs & {'js', 'attr_unquoted', 'attr_single', 'attr_double'}
        # 꺾쇠가 이스케이프 없이 생존 = 태그 주입 가능 → 도달 입증
        if {'<', '>'} <= survived:
            return _CLS_REACHED, f"반사+꺾쇠생존(컨텍스트={','.join(sorted(ctxs))}) → 도달 입증"
        # 실행 컨텍스트 반사지만 꺾쇠 escape — 따옴표 breakout 여지(미확인) → 정황
        if exec_ctx:
            return _CLS_SUGGESTIVE, f"실행 컨텍스트 반사({','.join(sorted(exec_ctx))}) — 꺾쇠 escape, breakout 미확인"
        return None, None
    # 서버 반사는 없지만 DOM 싱크 반사 의심(JS가 URL→innerHTML 등). 단 이건 '이 param이 싱크에
    # 닿는다'를 측정한 게 아니라 '페이지에 DOM-XSS 모양 코드가 있다'는 약한 정적 신호다
    # (innerHTML/location은 현대 페이지에 흔함). 그래서 '측정된 도달(REACHED)'이 아니라 '정황
    # (SUGGESTIVE)'로 둔다 — 실제 SQL 증거(0.70+)가 올바르게 이기고, 다른 신호가 없으면 XSS가
    # 최상위라 그대로 돌아 브라우저가 확정/기각한다(미발화면 strategy가 미보고).
    if refl.get('dom_suspect'):
        return _CLS_SUGGESTIVE, f"DOM 반사 의심({refl.get('dom_source')}→{refl.get('dom_sink')}) — 정적 신호, 브라우저 확정 필요"
    return None, None


def _filter_map_evidence(filter_map: dict[str, str] | None) -> dict[str, tuple[float, str]]:
    """토큰별 필터 지도(outcome: passed/removed/encoded/rejected) → 유형별 정황(SUGGESTIVE)
    증거. FILTER_PROBE_TOKENS에서 자기 유형에만 기여한다(따옴표 차단이 xss로 번지지 않음).

    'removed'(입력 제거)·'rejected'(차단 페이지)만 기여한다 — '그 유형을 의식한 필터'라 정황.
    'encoded'(출력 이스케이프, 예: '→&#39;)는 기여하지 않는다 — 그건 그 공격을 '중화'한 것이라
    성공 신호가 아니고, 특히 백엔드 주입형(sqli 등)은 출력 인코딩과 무관(char는 쿼리에 그대로
    도달)하므로 'encoded'를 필터로 세면 가짜 신호가 된다. 'passed'도 당연히 제외."""
    if not filter_map:
        return {}
    by_vuln: dict[str, list[str]] = {}
    for token, outcome in filter_map.items():
        if outcome not in ('removed', 'rejected'):
            continue
        for vuln in FILTER_PROBE_TOKENS.get(token, {}):
            by_vuln.setdefault(vuln, []).append(f"{token}({outcome})")
    return {v: (_CLS_SUGGESTIVE, f"필터된 토큰 {toks}") for v, toks in by_vuln.items()}


def _assemble_hints(field_hints: dict, group: dict, t_boost: dict,
                    db: dict, block_ratio: float):
    """prior(이름/형제/스택)와 recon 증거 클래스를 밴드 모델로 합쳐 최종 hints를 만든다.

    반환: (hints, group_note, recon_note, filter_map_note) — breakdown 표시용 노트 포함."""
    # PRIOR — 필드명 + 형제 상속 + 기술스택(전부 max, 증거 밴드엔 못 들어감)
    prior = _with_group_hints(field_hints, group or {})
    group_note = _group_hint_note(field_hints, prior)
    for vuln, w in (t_boost or {}).items():
        prior[vuln] = max(prior.get(vuln, 0.0), w)

    # EVIDENCE — 유형별 최상위 증거 클래스
    evidence: dict[str, tuple[float, str]] = {}
    sb, sn = _sqli_evidence(db, block_ratio)
    if sb is not None:
        evidence['sqli'] = (sb, sn)
    xb, xn = _xss_evidence(db)
    if xb is not None:
        evidence['xss'] = (xb, xn)
    for vuln, (b, n) in _filter_map_evidence(db.get('filter_map')).items():
        if vuln not in evidence or b > evidence[vuln][0]:
            evidence[vuln] = (b, n)

    # BUILD — 밴드 결합
    hints = {
        vuln: _banded(evidence.get(vuln, (None, None))[0], prior.get(vuln, 0.0))
        for vuln in set(prior) | set(evidence)
    }

    recon_note = evidence.get('sqli', (None, None))[1]
    other_notes = '; '.join(f"{v}: {n}" for v, (b, n) in evidence.items()
                            if v != 'sqli' and n)
    return hints, group_note, recon_note, (other_notes or None)


def _reflection_extra(db: dict) -> dict:
    """recon의 reflection 신호를 surface.extra로 옮긴다. reflects_html(=꺾쇠가 이스케이프
    없이 반사됨)은 XSS can_handle/priority가 쓰는 게이팅 불리언 — 반사 출처만 engine에서
    recon으로 옮겼을 뿐 판정 정책은 그대로다. 전체 reflection(contexts/survived)은 XSS가
    발사 전 컨텍스트·메타문자 프루닝에 쓴다."""
    refl = db.get('reflection')
    survived = (refl or {}).get('survived') or ()
    reflects_html = bool(refl and (
        refl.get('dom_suspect')
        or (refl.get('reflected') and '<' in survived and '>' in survived)))
    return {'reflection': refl, 'reflects_html': reflects_html}


def _blind_value(db: dict, hints: dict, response_type: str, waf_blocked: bool) -> bool | None:
    """blind 여부 결정값. recon이 반사를 측정했으면(reflection) 그 측정값이 진실이다 —
    reflected면 blind=False. 측정이 없으면(recon 미커버 표면이거나 프로브 실패) 정적
    추론으로 fallback하고, 그런 표면은 engine의 _verify_blind가 따로 프로브한다."""
    if waf_blocked:
        return None
    refl = db.get('reflection')
    if refl is not None:
        return not refl.get('reflected')
    return _infer_blind(hints, response_type)


def _infer_blind(hints: dict, response_type: str) -> bool | None:
    """정적 추론: hints + response_type으로 blind 여부 초기값 결정."""
    # sqli >= 0.7 → 인증 계열 필드 → 기술 스택 boost로 xss가 높아져도 blind 우선
    if hints.get('sqli', 0) >= 0.7:
        return True
    # xss/ssti는 반사가 전제인 취약점 → reflected
    if hints.get('xss', 0) >= 0.5 or hints.get('ssti', 0) >= 0.5:
        return False
    # JSON 응답은 입력을 그대로 반사하지 않음 → blind
    if response_type == 'json':
        return True
    return None


def _infer_response_type(surface_type: str, enctype: str | None, response_headers: list | dict | None) -> str:
    """응답 형식을 추론한다."""
    # url_param은 페이지 자체가 응답 → html
    if surface_type in ('url_param', 'hidden_param'):
        return 'html'

    # response_headers에서 Content-Type 확인
    ct = ''
    if isinstance(response_headers, dict):
        ct = response_headers.get('content-type', '') or response_headers.get('Content-Type', '')
    elif isinstance(response_headers, list):
        for h in response_headers:
            if isinstance(h, dict) and h.get('name', '').lower() == 'content-type':
                ct = h.get('value', '')
                break
    if isinstance(ct, list):
        ct = ct[0] if ct else ''
    ct = (ct or '').lower()
    if 'application/json' in ct:
        return 'json'
    if 'text/html' in ct:
        return 'html'

    # response_headers 없으면 요청 enctype으로 추론
    if enctype and 'application/json' in enctype:
        return 'json'

    return 'unknown'


def _should_skip(field_name: str) -> bool:
    return field_name.lower().replace('-', '_') in _SKIP_FIELDS


class Profiler:
    """수집된 page/button_result 레코드에서 공격 표면을 추출한다."""

    def profile_page(self, page: dict) -> list[AttackSurface]:
        surfaces = []
        tech_stack = page.get('tech_stack') or {}
        t_boost, tech_matches = _tech_boost(tech_stack)
        group_hints = _collect_group_hints(page)

        recon = page.get('recon') or {}
        resp_headers = page.get('response_headers')
        waf_info = page.get('waf_info')

        # URL 파라미터
        for param in (page.get('params') or {}):
            if _should_skip(param):
                continue
            field_hints, field_matches = _field_hints(param)
            db = (recon.get(param) or {}).get('db') or {}
            waf_blocked = db.get('waf_blocked', False)
            hints, group_note, recon_note, filter_map_note = _assemble_hints(
                field_hints, group_hints.get((page['url'].split('?')[0], 'GET'), {}),
                t_boost, db, recon.get('__block_ratio__', 0.0))
            rt = _infer_response_type('url_param', None, resp_headers)
            surfaces.append(AttackSurface(
                surface_type='url_param',
                url=page['url'].split('?')[0],
                method='GET',
                param=param,
                page=page,
                response_type=rt,
                blind=_blind_value(db, hints, rt, waf_blocked),
                extra={
                    'hints':       hints,
                    'waf_blocked': waf_blocked,
                    'waf_info':    waf_info,
                    'quote_char':  db.get('quote_char'),
                    'detected_db': db.get('detected_db'),
                    'filter_map':  db.get('filter_map'),
                    'behavior':    db.get('behavior'),
                    **_reflection_extra(db),
                    'breakdown': {
                        'field_matches': field_matches,
                        'tech_matches':  tech_matches,
                        'db_hint':       db.get('db_hint'),
                        'recon_note':    recon_note,
                        'group_note':    group_note,
                        'filter_map_note': filter_map_note,
                    },
                },
            ))

        # 폼 필드
        for form in (page.get('forms') or []):
            action  = form.get('action') or page['url']
            method  = form.get('method', 'GET').upper()
            enctype = form.get('enctype', 'application/x-www-form-urlencoded')
            # 이름뿐 아니라 크롤링 시점의 실제 값도 같이 넘긴다 — strategy가 co-submit할 때
            # 'test' 대신 진짜 값(숫자 ID 등)을 쓸 수 있어야 산술 프로브 같은 게 제대로 동작함
            all_params = {
                inp['name']: (inp.get('value') or 'test')
                for inp in form.get('inputs', [])
                if inp.get('name') and not _should_skip(inp['name'])
            }
            group = group_hints.get((action, method), {})
            for inp in form.get('inputs', []):
                param = inp.get('name')
                if not param or _should_skip(param):
                    continue
                if inp.get('type') in ('submit', 'button', 'image', 'reset'):
                    continue
                field_hints, field_matches = _field_hints(param)
                db = (recon.get(param) or {}).get('db') or {}
                waf_blocked = db.get('waf_blocked', False)
                hints, group_note, recon_note, filter_map_note = _assemble_hints(
                    field_hints, group, t_boost, db, recon.get('__block_ratio__', 0.0))
                rt = _infer_response_type('form_field', enctype, resp_headers)
                surfaces.append(AttackSurface(
                    surface_type='form_field',
                    url=action,
                    method=method,
                    param=param,
                    page=page,
                    response_type=rt,
                    blind=_blind_value(db, hints, rt, waf_blocked),
                    extra={
                        'hints':          hints,
                        'waf_blocked':    waf_blocked,
                        'waf_info':       waf_info,
                        'quote_char':     db.get('quote_char'),
                        'detected_db':    db.get('detected_db'),
                        'filter_map':     db.get('filter_map'),
                        'behavior':       db.get('behavior'),
                        'enctype':        enctype,
                        'all_params':     all_params,
                        'proxy_template': form.get('proxy_template'),
                        'proxy_field':    form.get('proxy_field'),
                        **_reflection_extra(db),
                        'breakdown': {
                            'field_matches': field_matches,
                            'tech_matches':  tech_matches,
                            'db_hint':       db.get('db_hint'),
                            'recon_note':    recon_note,
                            'group_note':    group_note,
                            'filter_map_note': filter_map_note,
                        },
                    },
                ))

        # 퍼징으로 발견된 hidden 파라미터
        for param in (page.get('hidden_params') or []):
            if _should_skip(param):
                continue
            field_hints, field_matches = _field_hints(param)
            db = (recon.get(param) or {}).get('db') or {}
            waf_blocked = db.get('waf_blocked', False)
            hints, group_note, recon_note, filter_map_note = _assemble_hints(
                field_hints, group_hints.get((page['url'].split('?')[0], 'GET'), {}),
                t_boost, db, recon.get('__block_ratio__', 0.0))
            rt = _infer_response_type('hidden_param', None, resp_headers)
            surfaces.append(AttackSurface(
                surface_type='hidden_param',
                url=page['url'].split('?')[0],
                method='GET',
                param=param,
                page=page,
                response_type=rt,
                blind=_blind_value(db, hints, rt, waf_blocked),
                extra={
                    'hints':       hints,
                    'waf_blocked': waf_blocked,
                    'waf_info':    waf_info,
                    'quote_char':  db.get('quote_char'),
                    'detected_db': db.get('detected_db'),
                    'filter_map':  db.get('filter_map'),
                    'behavior':    db.get('behavior'),
                    **_reflection_extra(db),
                    'breakdown': {
                        'field_matches': field_matches,
                        'tech_matches':  tech_matches,
                        'db_hint':       db.get('db_hint'),
                        'recon_note':    recon_note,
                        'group_note':    group_note,
                        'filter_map_note': filter_map_note,
                    },
                },
            ))

        # 퍼징으로 발견된 숨겨진 POST 폼 파라미터 (scanner.py의 _fuzz_post_params) —
        # form_field와 마찬가지로 all_params(known 필드 더미값)를 같이 실어 보내야
        # SQLiStrategy._base_fields가 나머지 필드를 채워서 정상적으로 요청을 구성한다.
        for entry in (page.get('hidden_post_params') or []):
            param = entry.get('param')
            if not param or _should_skip(param):
                continue
            field_hints, field_matches = _field_hints(param)
            group_key = (entry.get('action') or page['url'].split('?')[0], 'POST')
            db = (recon.get(param) or {}).get('db') or {}
            waf_blocked = db.get('waf_blocked', False)
            hints, group_note, recon_note, filter_map_note = _assemble_hints(
                field_hints, group_hints.get(group_key, {}), t_boost, db,
                recon.get('__block_ratio__', 0.0))
            enctype = entry.get('enctype') or 'application/x-www-form-urlencoded'
            rt = _infer_response_type('hidden_param', enctype, resp_headers)
            # scanner.py가 이 파라미터를 발견할 때 공격적 프로브 값이 필터에 막혀서 특정
            # EVASION_TRANSFORMS 기법으로 우회한 적이 있으면(evasion_used), 그 기법 이름을
            # 넘겨준다 — 'blocked'(우회 전부 실패했지만 그래도 기록함)는 실제로 통한 기법이
            # 아니라서 제외한다. sqli.py가 이 필드에서 처음 WAF 차단을 만났을 때 전체 우회
            # 탐색(7종+조합) 대신 이 기법부터 먼저 시도해서 요청을 아낄 수 있게 하기 위함.
            discovery_evasion = entry.get('evasion_used')
            if discovery_evasion == 'blocked':
                discovery_evasion = None
            surfaces.append(AttackSurface(
                surface_type='hidden_param',
                url=entry.get('action') or page['url'].split('?')[0],
                method='POST',
                param=param,
                page=page,
                response_type=rt,
                blind=_blind_value(db, hints, rt, waf_blocked),
                extra={
                    'hints':       hints,
                    'waf_blocked': waf_blocked,
                    'waf_info':    waf_info,
                    'quote_char':  db.get('quote_char'),
                    'detected_db': db.get('detected_db'),
                    'filter_map':  db.get('filter_map'),
                    'behavior':    db.get('behavior'),
                    'enctype':     enctype,
                    'all_params':  entry.get('known_fields') or {},
                    'discovery_evasion': discovery_evasion,
                    **_reflection_extra(db),
                    'breakdown': {
                        'field_matches': field_matches,
                        'tech_matches':  tech_matches,
                        'db_hint':       db.get('db_hint'),
                        'recon_note':    recon_note,
                        'group_note':    group_note,
                        'filter_map_note': filter_map_note,
                    },
                },
            ))

        return surfaces

    def profile_button(self, button_result: dict, pages: list[dict] | None = None) -> list[AttackSurface]:
        surfaces = []
        page_url   = button_result.get('page_url', '')
        # page_url과 일치하는 page 레코드에서 tech_stack을 가져와 boost 적용
        matched_page = next((p for p in (pages or []) if p.get('url', '').split('?')[0] == page_url.split('?')[0]), None)
        t_boost, tech_matches = _tech_boost(matched_page.get('tech_stack') or {}) if matched_page else ({}, [])
        waf_info = matched_page.get('waf_info') if matched_page else None
        for call in (button_result.get('api_calls') or []):
            action = call.get('url', page_url)
            method = call.get('method', 'POST').upper()
            # 버튼 클릭으로 캡처한 API 호출은 필드명만 알 수 있고 실제 값은 모름 → 'test'로 채움
            all_params = {f: 'test' for f in call.get('fields', []) if not _should_skip(f)}
            for field_name in call.get('fields', []):
                if _should_skip(field_name):
                    continue
                enctype = call.get('content_type', 'application/json')
                field_hints, field_matches = _field_hints(field_name)
                hints, _, _, _ = _assemble_hints(field_hints, {}, t_boost, {}, 0.0)
                rt = _infer_response_type('api_field', enctype, button_result.get('response_headers'))
                surfaces.append(AttackSurface(
                    surface_type='api_field',
                    url=action,
                    method=method,
                    param=field_name,
                    page={'url': page_url, 'tech_stack': {}},
                    response_type=rt,
                    blind=_infer_blind(hints, rt),
                    extra={
                        'hints':      hints,
                        'waf_info':   waf_info,
                        'enctype':    enctype,
                        'all_params': all_params,
                        'breakdown': {
                            'field_matches': field_matches,
                            'tech_matches':  tech_matches,
                            'db_hint':       None,
                            'recon_note':    None,
                        },
                    },
                ))
        return surfaces
