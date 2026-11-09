"""범용 응답/텍스트 비교 유틸 — 도메인 지식(필터/WAF/SQL) 없이 "두 응답이 실제로 다른가"만
본다. recon의 필터맵 노이즈 측정, 전략의 boolean/blind/ORDER BY 경계 판정, scanner의 POST
퍼징 변화 측정이 전부 공유한다. (예전 waf.py/validation.py에 섞여 있던 범용 함수를 분리.)"""

import difflib

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
