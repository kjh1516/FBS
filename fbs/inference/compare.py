"""두 응답이 실제로 다른지만 비교하는 공용 함수다. 필터·WAF·SQL 판단은 하지 않고 달라졌는지만 본다.
recon·전략·scanner가 공유한다."""

import difflib
import random
import string

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


# ── 엔드포인트 반응 프로파일 (noise/stateful/accumulating/input_sensitive) ──────────
# 엔드포인트가 입력에 어떻게 반응하는지 한 번에 재는 공용 함수다. recon이 (url,method)마다
# 한 번만 재고, SQLi·필터맵·profiler가 그 결과를 재사용한다.

STATEFUL_NOISE_THRESHOLD = 30  # 같은 입력인데 이만큼 넘게 흔들리면 응답이 불안정(stateful)해서 내용 비교를 못 믿는다


def _rand_token(n: int = 10) -> str:
    """필터·반사에 안 걸리는 평범한 영숫자 토큰. 순수하게 반응만 재려고 쓴다."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def profile_response(probe, *, k: int = 5, m: int = 2, floor: int = 1,
                     stateful_threshold: int = STATEFUL_NOISE_THRESHOLD) -> dict:
    """엔드포인트 반응 특성을 재서 {noise, stateful, accumulating, input_sensitive}로 반환한다.

    probe(value) -> (status, body): value를 대상 필드에 넣어 보내고 (상태코드, 본문)을 받는
    함수다. 어떻게 보낼지는 호출부가 정하고, 여기선 뭘 보내고 어떻게 해석할지만 담당한다.

    재는 것:
      · 같은 영숫자 입력 K번 → noise(응답이 저절로 흔들리는 정도), stateful(noise가 임계 초과),
        accumulating(응답 길이가 매번 꾸준히 늘면 입력이 쌓이는 형태)
      · 서로 다른 영숫자 M개 → input_sensitive(noise 넘는 변화가 나면 입력이 응답에 반영됨).
        False면 입력과 무관한 고정 응답이라 stub/인증벽이고 공격 가치가 없다.
        
    K를 5 이상 두는 건 5번째에 초기화되는 식의 주기적 변화까지 잡기 위해서다.
    stateful 페이지에선 노이즈가 신호를 가려서 input_sensitive를 덜 믿는다(어쩔 수 없는 한계)."""
    anchor = _rand_token()
    texts: list[str] = []
    for _ in range(max(k, 2)):
        st, body = probe(anchor)
        texts.append(visible_text(body) if st is not None else (texts[-1] if texts else ''))

    noise = max((diff_score(texts[0], t) for t in texts[1:]), default=0)
    stateful = noise > stateful_threshold

    len_deltas = [len(texts[i + 1]) - len(texts[i]) for i in range(len(texts) - 1)]
    accumulating = (
        len(len_deltas) >= 2
        and all(d > floor for d in len_deltas)
        and min(len_deltas) >= 0.5 * max(len_deltas)
    )

    ref, gate = texts[0], max(noise, floor)
    input_sensitive = False
    seen = {anchor}
    for _ in range(m):
        tok = _rand_token()
        while tok in seen:
            tok = _rand_token()
        seen.add(tok)
        st, body = probe(tok)
        if st is None:
            continue
        if diff_score(ref, visible_text(body)) > gate:
            input_sensitive = True
            break

    return {
        'noise': noise,
        'stateful': stateful,
        'accumulating': accumulating,
        'input_sensitive': input_sensitive,
        'samples': len(texts),
    }
