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
    """

    @abstractmethod
    def can_handle(self, surface: 'AttackSurface') -> bool:
        """이 strategy가 해당 공격 표면을 처리할 수 있으면 True."""

    @abstractmethod
    def run(self, surface: 'AttackSurface') -> list['VulnResult']:
        """probe → analyze → reattack 전 과정을 실행하고 결과를 반환."""
