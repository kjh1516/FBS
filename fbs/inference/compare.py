"""두 응답이 실제로 다른지만 비교하는 공용 함수다. 필터·WAF·SQL 판단은 하지 않고 달라졌는지만 본다.
recon·전략·scanner가 공유한다."""

import difflib

from bs4 import BeautifulSoup


def visible_text(body: str) -> str:
    """태그·script·style을 걷어내고 눈에 보이는 텍스트만 남긴다. CSRF 토큰이나 타임스탬프처럼
    요청마다 바뀌는 값이 비교에 끼면 오판하기 쉬워서 미리 제거한다."""
    if not body:
        return ''
    soup = BeautifulSoup(body, 'html.parser')
    for tag in soup(['script', 'style']):
        tag.decompose()
    return soup.get_text(separator=' ', strip=True)


def diff_score(text_a: str, text_b: str) -> int:
    """두 텍스트에서 바뀐(추가·삭제·교체) 구간 길이의 합이다. 전체 길이만 보면 길이는 같아도
    내용만 바뀐 경우를 놓쳐서, 길이 대신 바뀐 양을 센다."""
    matcher = difflib.SequenceMatcher(None, text_a, text_b, autojunk=False)
    return sum(
        max(i2 - i1, j2 - j1)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        if tag != 'equal'
    )




# ── 리다이렉트-인지 응답 관측 (추론 공용) ──────────────────────────────────────
# 추론 단계는 기본적으로 리다이렉트를 따라가지 않는다(allow_redirects=False). 302를 따라가면
# 목적지 본문이 측정에 섞여 신호가 오염되기 때문이다. 대신 (status, Location, 본문)을 그대로
# 관측해 비교하고, 의미 있는 302만 resolve_redirect로 한 번 따로 확인한다.

_STRONG_DIFF = 10_000  # status/Location이 다를 때 주는 차이값 — 어떤 노이즈 임계도 확실히 넘긴다


def observe(status, body, location=None) -> dict:
    """raw 응답(리다이렉트 안 따라감)을 비교 가능한 관측으로 정규화한다. 302를 따라가지 않고도
    (status, location, text)로 신호를 본다."""
    return {
        'status':   status,
        'location': location,
        'redirect': status is not None and 300 <= status < 400,
        'text':     visible_text(body) if status is not None else '',
    }


def observations_differ(a: dict, b: dict) -> int:
    """두 관측의 차이 점수. status가 다르거나, 같은 status인데 Location이 다르면(본문은 같고
    목적지만 다른 로그인 폼 케이스) 노이즈를 확실히 넘는 큰 값을, 아니면 본문 diff를 준다."""
    if a.get('status') != b.get('status'):
        return _STRONG_DIFF
    if a.get('location') != b.get('location'):
        return _STRONG_DIFF
    return diff_score(a.get('text', ''), b.get('text', ''))


def resolve_redirect(location, fetch_fn, *, in_scope, cache,
                     baseline_location=None, known_paths=()) -> dict | None:
    """302 목적지를 선별적으로 한 번만 따로 확인(재추종)한다.

    따라가는 건 의미 있는 302뿐 — baseline이 가던 곳과 다르거나, 크롤이 못 본 신규 path일 때.
    그리고 in_scope여야 한다(외부 도메인엔 안 감). 실제 재요청은 fetch_fn이 수행한다 — 세션·쿠키
    격리·추종은 호출부(recon/전략)가 책임진다(함수에 probe/fetch를 주입받는 것과 같은 패턴).
    결과는 cache에 path당 한 번만 저장한다.

    fetch_fn(location) -> (status, body, final_location) | None.
    반환: observe() 관측(따라간 목적지) 또는 None(재추종 안 함/실패)."""
    if not location or location in cache:
        return cache.get(location)
    if not in_scope(location):
        cache[location] = None
        return None
    meaningful = (location != baseline_location) or (location not in known_paths)
    if not meaningful:
        cache[location] = None
        return None
    result = fetch_fn(location)
    obs = observe(*result) if result is not None else None
    cache[location] = obs
    return obs
