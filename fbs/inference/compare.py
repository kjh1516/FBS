"""범용 응답/텍스트 비교 유틸 — 도메인 지식(필터/WAF/SQL) 없이 "두 응답이 실제로 다른가"만
본다. recon의 필터맵 노이즈 측정, 전략의 boolean/blind/ORDER BY 경계 판정, scanner의 POST
퍼징 변화 측정이 전부 공유한다. (예전 waf.py/validation.py에 섞여 있던 범용 함수를 분리.)"""

import difflib
import random
import string

from bs4 import BeautifulSoup


def visible_text(body: str) -> str:
    """HTML 태그·스크립트·스타일을 걷어내고 눈에 보이는 텍스트만 남긴다. hidden input 값,
    CSRF 토큰, script 안의 타임스탬프처럼 요청마다 바뀌는 잡음이 raw body 길이/문자 비교에
    그대로 섞여 들어가면 실제 신호(응답 행 수 변화 등)가 노이즈에 묻혀 오판하기 쉽다 —
    정규화된 텍스트로 비교하면 이런 잡음이 상당수 걸러진다."""
    if not body:
        return ''
    soup = BeautifulSoup(body, 'html.parser')
    for tag in soup(['script', 'style']):
        tag.decompose()
    return soup.get_text(separator=' ', strip=True)


def diff_score(text_a: str, text_b: str) -> int:
    """두 텍스트 사이 실제로 달라진(삽입/삭제/치환) 구간 길이의 합 — difflib opcode 기반.
    전체 길이 차이만 보면 "길이는 비슷한데 일부만 바뀐" 미세한 변화를 놓치기 때문에,
    boolean/blind/ORDER BY 경계 탐지/POST 파라미터 퍼징이 전부 이 함수를 공용으로 쓴다."""
    matcher = difflib.SequenceMatcher(None, text_a, text_b, autojunk=False)
    return sum(
        max(i2 - i1, j2 - j1)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        if tag != 'equal'
    )


# ── 엔드포인트 반응 프로파일 (noise/stateful/accumulating/input_sensitive) ──────────
# "엔드포인트가 요청에 어떻게 반응하나"를 한 번에 측정하는 공용 프리미티브. 예전엔 SQLi
# _probe_idempotency(멱등/노이즈)와 필터맵의 누적(memo) 가드로 흩어져 있던 걸 통합했고,
# 입력-무관 응답(stub/인증벽) 감지를 같이 넣었다. recon이 (url,method)마다 1회 측정해
# 하류(SQLi·필터맵·profiler)가 재측정 없이 소비한다.

STATEFUL_NOISE_THRESHOLD = 30  # 같은 입력 반복 시 이 이상 흔들리면 stateful(content 오라클 불가)


def _rand_token(n: int = 10) -> str:
    """중립 영숫자 토큰 — 필터/반사와 안 섞이게(처리 민감도만 격리 측정)."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def profile_response(probe, *, k: int = 5, m: int = 2, floor: int = 1,
                     stateful_threshold: int = STATEFUL_NOISE_THRESHOLD) -> dict:
    """엔드포인트 반응 특성 측정 → {noise, stateful, accumulating, input_sensitive}.

    probe(value: str) -> (status: int|None, body: str): value를 대상 필드에 넣어 보내고
    (상태코드, 본문)을 돌려주는 콜러블. 전송 방식(recon 세션/전략 등)은 호출부가 책임지고,
    여기선 '무엇을 보내 어떻게 해석하나'만 담당한다(try_evade·probe_filter_map와 같은 패턴).

    측정:
      · 같은 중립 영숫자 입력 K회 → noise(첫 샘플 대비 최대 diff), stateful(noise>임계),
        accumulating(연속 길이 증가분이 전부 양수+일정 = memo형)
      · 서로 다른 랜덤 영숫자 M개 → input_sensitive(diff가 noise를 넘으면 입력이 응답에 반영됨).
        False면 입력과 무관한 응답 = stub/인증벽 → 공격 가치 없음.
    K≥5인 건 '5회째 리셋' 같은 주기적 상태 변화까지 관측하기 위함(SQLi 기존 보정 유지).
    stateful 페이지에선 input_sensitive 신뢰도가 낮다(노이즈가 신호를 가림) — 의도된 한계."""
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
