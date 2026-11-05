"""DB 엔진(SQLite/MySQL/PostgreSQL 등) 관련 정보를 한 곳에 모아둔 공용 모듈.

recon.py(에러 메시지로 가볍게 힌트만)와 sqli.py(SQLiStrategy, 실제 추출 페이로드 구성 +
확정 판정) 양쪽에서 같은 DB 판별 결과를 써야 서로 다른 결론이 안 나온다 — 예전엔
ERROR_SIGNATURES가 두 파일에 각각 따로 정의돼 있다가 SQLite 항목이 미묘하게 갈라진
적이 있어서(recon은 'no such function', sqli는 'no such function: sleep'), 이제 여기
하나로 합쳤다.

SQL_DIALECTS는 SQLiStrategy의 blind boolean 추출이 DB 엔진마다 다른 함수/문법을 쓸 수
있게 해주는 방언 테이블. LENGTH()는 SQLite/MySQL/PostgreSQL 세 곳 다 동일해서 여기
포함하지 않고 호출부에서 그대로 하드코딩한다.

current_db가 None인 건 "그 DB엔 현재 DB명이라는 개념 자체가 없다"는 뜻이 아니라
(SQLite는 파일 하나가 곧 DB라 이름 개념이 약함) — blind 추출의 첫 단계(db명 알아내기)를
스킵하고 바로 테이블 열거로 넘어가라는 신호로 쓴다.
"""

SQL_DIALECTS: dict[str, dict] = {
    'SQLite': {
        'ord_fn':     lambda x: f"UNICODE({x})",
        'substr_fn':  lambda x, p, l: f"SUBSTR({x},{p},{l})",
        'concat':     lambda a, b: f"{a}||{b}",
        'current_db': None,
        'version_fn': "sqlite_version()",
    },
    'MySQL': {
        'ord_fn':     lambda x: f"ASCII({x})",
        # SUBSTR은 MySQL에서 SUBSTRING의 별칭이라 동작이 같으면서, 'substring'을 밴하는
        # 필터를 피한다. SUBSTR도 밴이면 MID로 바꿔야 하지만 그건 추후.
        'substr_fn':  lambda x, p, l: f"SUBSTR({x},{p},{l})",
        'concat':     lambda a, b: f"CONCAT({a},{b})",
        'current_db': "database()",
        'version_fn': "@@version_compile_os",
    },
    'PostgreSQL': {
        'ord_fn':     lambda x: f"ASCII({x})",
        'substr_fn':  lambda x, p, l: f"SUBSTR({x},{p},{l})",
        'concat':     lambda a, b: f"{a}||{b}",
        'current_db': "current_database()",
        'version_fn': "version()",
    },
}

# _resolve_dialect가 시도할 순서 — 흔한 순서대로 두면 평균 요청 수가 줄어든다.
DIALECT_PROBE_ORDER = ['SQLite', 'MySQL', 'PostgreSQL']


# recon.py/sqli.py가 각자 따로 들고 있던 것을 통합 — SQL_DIALECTS(3종)보다 넓게
# MSSQL/Oracle까지 포함한다(에러 시그니처 매칭은 추출 문법과 달리 이 두 엔진도 커버 가능).
ERROR_SIGNATURES: dict[str, list[str]] = {
    'SQLite':     ['sqlite3.operationalerror', 'sqlite3.interfaceerror',
                   'no such function', 'unrecognized token'],
    'MySQL':      ['you have an error in your sql syntax', 'mysql_fetch',
                   'mysqli_', 'warning: mysql'],
    'PostgreSQL': ['pg_query()', 'psycopg2', 'postgresql',
                   'unterminated quoted string'],
    'MSSQL':      ['microsoft sql server', 'odbc sql server',
                   'unclosed quotation mark'],
    'Oracle':     ['ora-', 'oracle error', 'quoted string not properly terminated'],
}


def detect_db_from_error(body: str) -> str | None:
    """응답 본문에 노출된 에러 메시지로 DB 엔진을 추측한다."""
    lower = body.lower()
    for db, sigs in ERROR_SIGNATURES.items():
        if any(sig in lower for sig in sigs):
            return db
    return None
