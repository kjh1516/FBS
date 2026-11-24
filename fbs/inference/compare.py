"""두 응답이 실제로 다른지만 비교하는 공용 함수다. 필터·WAF·SQL 판단은 하지 않고 달라졌는지만 본다.
recon·전략·scanner가 공유한다."""

import difflib
import random
import string

from bs4 import BeautifulSoup


def probe_token(prefix: str) -> str:
    """필터·SQL에 안 걸리는 영숫자 프로브 토큰을 만든다. 응답에 이 토큰이 그대로 박혀 있으면
    입력이 반사된 것으로 본다. 매 호출 달라서 메모형(이전 입력 잔존) 판정과 페이지에 원래
    있던 텍스트와의 우연한 충돌을 피한다. 크롤러·recon·전략이 공유하되, prefix로 어느 단계·
    필드에서 보낸 토큰인지 응답에서 바로 식별할 수 있게 한다(예: 퍼징 fbsfz, 반사 fbsrf)."""
    return prefix + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


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


# ── 동적 영역 마스킹 ──────────────────────────────────────────────────────────
# 같은 페이지를 두 번 받아(제출 없는 GET 2회 등) 비교하면 요청마다 저절로 바뀌는 구간(광고·타임스탬프·
# nonce 등)이 드러난다. 그 구간의 앞뒤에 붙은 고정 텍스트를 앵커로 뽑아두고, 이후 어떤 응답이든 그
# 앵커로 변동 구간을 찾아 지운다. 내용이 매번 달라지거나 앞쪽 길이가 바뀌어 위치가 밀려도 앵커 텍스트로
# 찾으므로 영향받지 않는다. diff_score는 그렇게 변동 구간을 뺀 텍스트끼리 비교한다(diff_score는 순수).

def volatile_anchors(a: str, b: str, ctx: int = 24) -> list[dict]:
    """두 샘플에서 달라지는 구간마다 (앞 앵커, 뒤 앵커, 예시)를 뽑는다. 앵커는 그 구간에 바로 붙은
    고정 텍스트(최대 ctx자)다. 둘 다 빈 앵커(페이지 전체가 변동)는 제외한다."""
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    anchors = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        # 변동 구간을 양옆 공백까지 넓혀 단어(토큰) 단위로 잡는다. difflib는 두 샘플의 최소 차이만 잡아
        # 변동 값의 일부가 공통으로 남을 수 있는데, 그러면 앵커에 변동 문자가 섞여 값이 다른 응답에서 못 찾는다.
        while i1 > 0 and not a[i1 - 1].isspace():
            i1 -= 1
        while i2 < len(a) and not a[i2].isspace():
            i2 += 1
        prefix = a[max(0, i1 - ctx):i1]
        suffix = a[i2:i2 + ctx]
        if not prefix and not suffix:
            continue
        sample = (a[i1:i2] or b[j1:j2])[:40]
        anchors.append({'prefix': prefix, 'suffix': suffix, 'sample': sample})
    return anchors


def strip_volatile(text: str, anchors: list[dict]) -> str:
    """앵커(앞/뒤 고정 텍스트)로 변동 구간을 찾아 그 사이 내용을 지운다(앵커는 남긴다). 내용이 매번
    바뀌어도, 앞 내용이 밀려도 앵커로 찾으므로 동적 요소만 빠진다. 앵커가 응답에 없으면 그 앵커는 건너뛴다."""
    if not text or not anchors:
        return text
    for anc in anchors:
        prefix, suffix = anc.get('prefix', ''), anc.get('suffix', '')
        start = 0 if not prefix else text.find(prefix)
        if start == -1:
            continue
        cut_from = start + len(prefix)
        end = len(text) if not suffix else text.find(suffix, cut_from)
        if end == -1:
            continue
        text = text[:cut_from] + text[end:]
    return text




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
