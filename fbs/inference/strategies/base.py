import time
from abc import ABC, abstractmethod

from fbs.inference.models import AttackSurface, VulnResult


class BaseStrategy(ABC):
    """모든 탐지 전략의 공통 인터페이스.

    각 구현체는 아래 4단계 흐름을 따른다:
      1. can_handle  — 이 표면을 처리할 수 있는지 판단
      2. probe       — 최소 페이로드로 반응 확인
      3. analyze     — 응답 분석 (WAF 여부, 반사 유형, DB 종류 등)
      4. reattack    — 분석 결과 기반 정밀 페이로드 전송
    run()은 위 흐름을 오케스트레이션한다.

    엔진은 한 공격 표면에 대해, can_handle이 True인 전략을 전부 돌리지 않고 priority()가 가장 높은
    하나만 실행한다. 그 우선순위는 기본적으로 profiler가 매긴 해당 취약점 유형(VULN_TYPE)의 hint
    점수다 — 즉 프로파일링에서 가장 유력하다고 본 유형이 이긴다.
    """

    # 이 전략이 대응하는 취약점 유형 키 (profiler hints의 키와 동일: 'sqli' | 'xss' | ...).
    VULN_TYPE: str = ''

    # HTTP 요청 타임아웃(초) 기본값 — 하위 전략이 필요시 재정의(예: SQLi time-based는 더 길게).
    TIMEOUT = 10

    @abstractmethod
    def can_handle(self, surface: 'AttackSurface') -> bool:
        """이 strategy가 해당 공격 표면을 처리할 수 있으면 True."""

    def priority(self, surface: 'AttackSurface') -> float:
        """이 표면에 대한 이 전략의 우선순위 점수. 기본은 profiler가 매긴 VULN_TYPE의 hint
        점수 — 엔진이 can_handle True인 전략들 중 이 값이 가장 큰 하나만 골라 실행한다.
        필드명 힌트 외의 신호(예: XSS의 reflects_html)를 반영하려면 하위 전략에서 재정의한다."""
        return surface.extra.get('hints', {}).get(self.VULN_TYPE, 0.0)

    def _base_fields(self, surface: 'AttackSurface') -> dict:
        """target 필드와 함께 보낼 나머지 필드의 기본값을 구성한다(SQLi·XSS 전략 공용).

        profiler가 크롤링 시점의 실제 값(form input value 등)을 all_params에 담아 넘기므로, 가능하면
        test 더미 대신 그 값을 그대로 쓴다 — 숫자형 필드 arithmetic 프로브 등이 여기에 의존한다."""
        if surface.surface_type == 'url_param':
            raw  = (surface.page or {}).get('params') or {}
            data = {k: (v[0] if isinstance(v, list) and v else 'test') for k, v in raw.items()}
        else:
            data = dict(surface.extra.get('all_params') or {})
        data.setdefault(surface.param, 'test')
        return data

    def _send(self, surface: 'AttackSurface', data: dict, timeout: int | None = None):
        """(status, body, elapsed) — 실패 시 (None, '', elapsed). GET은 쿼리스트링, JSON enctype은
        json=, 그 외는 form data=로 보낸다. SQLi·XSS 전략 공용(self.session/self.TIMEOUT 사용)."""
        timeout = timeout or self.TIMEOUT
        enctype = surface.extra.get('enctype') or ''
        # allow_redirects=False — 탐지 프로브는 리다이렉트를 따라가지 않는다. 따라가면 목적지
        # 본문이 참/거짓 비교에 섞여 오라클이 뒤집히거나 평탄화된다. 302는 raw로 관측한다.
        start = time.monotonic()
        try:
            if surface.method == 'GET':
                resp = self.session.get(surface.url, params=data, timeout=timeout, allow_redirects=False)
            elif 'application/json' in enctype:
                resp = self.session.request(surface.method, surface.url, json=data, timeout=timeout, allow_redirects=False)
            else:
                resp = self.session.request(surface.method, surface.url, data=data, timeout=timeout, allow_redirects=False)
            status = resp.status_code
            # 302는 안 따라가서 본문이 비어 있다. 목적지(Location)를 본문에 실어, 본문 diff를 쓰는
            # 기존 오라클(boolean/반사 등)이 "다른 데로 리다이렉트됨"을 자동으로 신호로 보게 한다 —
            # 같은 302라도 목적지가 다르면 다른 본문이 되어 로그인 우회 같은 신호가 살아난다.
            body = f"[redirect {status} {resp.headers.get('Location', '')}]" if 300 <= status < 400 else resp.text
            return status, body, time.monotonic() - start
        except Exception:
            return None, '', time.monotonic() - start

    @abstractmethod
    def run(self, surface: 'AttackSurface') -> list['VulnResult']:
        """probe → analyze → reattack 전 과정을 실행하고 결과를 반환."""
