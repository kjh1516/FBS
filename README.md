# FBS — From-scratch Blackbox Scanner

Scrapy + Playwright 기반의 공부에 목적을 둔 범용 웹 취약점 스캐너입니다. Dreamhack 워게임을 기반으로 구현 중이며, 블랙박스 스캐너를 지향 합니다. 현재는 워게임을 제외한 타 사이트에서는 정상적으로 동작하지 않을 수 있습니다. 


## 아키텍처 — 2단계 분리형

```
[단계 A: 크롤링]                      [단계 B: 추론]
Scrapy + Playwright                   SQLite 읽기
  ├ 폼/URL 파라미터 수집                ├ Recon  (반사·필터맵·WAF·노출파일·기술스택)
  ├ 숨은 파라미터 퍼징                  ├ Profiler (증거 클래스 기반 우선순위 점수)
  ├ SPA 버튼 클릭 → XHR 가로채기   →    └ Strategy (표면별 최우선 전략 1개 실행)
  └ 로그인/세션 유지                         ├ SQLiStrategy
          │                                  └ XSSStrategy
          ▼                                        │
     SQLite (fbs_results.db)  ───────────────────▶ vuln_report.json
```

크롤러와 추론 엔진을 DB로 분리해, 한 번 크롤한 결과로 추론을 반복·디버깅할 수 있고 각 단계를 독립적으로 발전시킵니다.

## 설치

```bash
pip install -r requirements.txt
playwright install chromium        # 헤드리스 브라우저 바이너리
```

- Python 3.10+ (3.11에서 테스트)

## 사용법

```bash
# 단계 A — 크롤링 (결과를 fbs_results.db에 저장)
scrapy crawl scanner -a target_url=http://TARGET/
#   로그인 필요 시:
scrapy crawl scanner -a target_url=http://TARGET/ -a login_id=ID -a login_pw=PW
```

## 탐지 범위

### SQL Injection
- 탐지: 따옴표 프로브 → 산술 → boolean(등가 클러스터 재검증) → error/time
- 열거/추출: `ORDER BY` → `UNION` → error-based 폴백, blind 추출(콘텐츠/시간 오라클 + 이진탐색)
- DB 핑거프린팅: 오라클 기반(방언 판별), WAF/필터 우회(인라인 주석·대소문자·공백·심볼릭 연산자 등 변형을 측정 적용)

### XSS
- **Reflected**: 중립 카나리로 반사 컨텍스트 분류 → 컨텍스트별 페이로드 → 브라우저 실행 확정

### Recon (공용 신호)
반사 여부·컨텍스트, 필터 지도(제거/인코딩/거부 구분), WAF 탐지(단어경계 매칭), 노출 파일, 캐시 헤더, 기술 스택 핑거프린팅


## 프로젝트 구조

```
fbs/
├─ spiders/scanner.py      # 단계 A: 크롤러 (Scrapy + Playwright)
├─ pipelines.py, items.py  # 크롤 결과 → SQLite
└─ inference/              # 단계 B: 추론 엔진
   ├─ engine.py            #   파이프라인 총괄
   ├─ recon.py             #   신호 수집 허브 (반사·필터맵·차단비율)
   ├─ profiler.py          #   증거 클래스 기반 우선순위 점수
   ├─ validation.py        #   필터·WAF 탐지(baseline 차분) + 우회 변형
   ├─ compare.py           #   범용 응답 비교 (visible_text·diff_score)
   ├─ sql_dialects.py      #   DB 방언 테이블
   └─ strategies/          #   취약점별 탐지·확정
      ├─ sqli.py
      └─ xss.py
```
