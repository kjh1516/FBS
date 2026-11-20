import sqlite3
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from fbs.items import PageItem, ButtonResultItem


# ── DB 스키마 (단일 출처) ──────────────────────────────────────────────────────
# 두 테이블의 컬럼을 여기 한곳에 정의한다. CREATE TABLE / 마이그레이션 / INSERT / 리포트 dict /
# engine의 JSON 디코드가 전부 이 목록을 순회해서 생성·복원되므로, 컬럼을 추가/변경할 땐 여기만 고치면
# 된다. 공통 컬럼 id(PK)·scan_id·scanned_at은 목록에서 빼고 CREATE 템플릿에만 둔다.
#   PAGE_COLUMNS   : (컬럼명, SQL 타입, JSON 직렬화 여부, 리포트용 기본값)
#   BUTTON_COLUMNS : (컬럼명, SQL 타입, JSON 직렬화 여부)
PAGE_COLUMNS = [
    ('status_code',        'INTEGER', False, None),
    ('content_type',       'TEXT',    False, None),
    ('depth',              'INTEGER', False, 0),
    ('method',             'TEXT',    False, None),
    ('params',             'TEXT',    True,  {}),
    ('response_headers',   'TEXT',    True,  []),
    ('cookies',            'TEXT',    True,  []),
    ('tech_stack',         'TEXT',    True,  {}),
    ('forms',              'TEXT',    True,  []),
    ('hidden_params',      'TEXT',    True,  []),
    ('hidden_post_params', 'TEXT',    True,  []),
    ('security_headers',   'TEXT',    True,  {}),
    ('page_signals',       'TEXT',    True,  {}),
]

BUTTON_COLUMNS = [
    ('page_url',               'TEXT', False),
    ('button',                 'TEXT', False),
    ('api_calls',              'TEXT', True),
    ('set_cookies',            'TEXT', True),
    ('response_headers',       'TEXT', True),
    ('cookie_changes',         'TEXT', True),
    ('localstorage_changes',   'TEXT', True),
    ('sessionstorage_changes', 'TEXT', True),
    ('dom_changes',            'TEXT', True),
]

# JSON으로 저장/복원되는 컬럼명만 — engine이 읽을 때 json.loads 대상 (목록에서 자동 파생)
PAGE_JSON_COLUMNS   = [n for n, _, is_json, _ in PAGE_COLUMNS   if is_json]
BUTTON_JSON_COLUMNS = [n for n, _, is_json    in BUTTON_COLUMNS if is_json]


class SQLitePipeline:
    PAGE_COLUMNS   = PAGE_COLUMNS      # self.PAGE_COLUMNS로 쓰던 기존 참조 유지
    BUTTON_COLUMNS = BUTTON_COLUMNS

    def __init__(self, db_path, target_url='', login_id=None, login_pw=None, user_agent=None):
        self.db_path     = db_path
        self._target_url = target_url
        self._login_id   = login_id
        self._login_pw   = login_pw
        self._user_agent = user_agent

    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            crawler.settings.get('SQLITE_DB_PATH', 'fbs_results.db'),
            crawler.settings.get('TARGET_URL', ''),
            crawler.settings.get('LOGIN_ID', None),
            crawler.settings.get('LOGIN_PW', None),
            crawler.settings.get('USER_AGENT', None),
        )

    def open_spider(self, spider=None):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self._create_tables()
        self._scan_id        = datetime.now(timezone.utc).isoformat()
        self._pages          = {}
        self._button_results = []
        print(f"\n# [DB] {self.db_path} | 대상: {self._target_url} | scan_id: {self._scan_id}")

    def close_spider(self, spider=None):
        self.conn.commit()
        self.conn.close()
        self._write_report()

        from fbs.inference.engine import InferenceEngine
        InferenceEngine(
            db_path=self.db_path,
            login_id=self._login_id,
            login_pw=self._login_pw,
            user_agent=self._user_agent,  # 크롤과 같은 UA(USER_AGENT 설정) 공유
        ).run()

    def _create_tables(self):
        page_cols_sql = ',\n                '.join(
            f'{name} {sql_type}' for name, sql_type, _, _ in self.PAGE_COLUMNS
        )
        btn_cols_sql = ',\n                '.join(
            f'{name} {sql_type}' for name, sql_type, _ in self.BUTTON_COLUMNS
        )
        self.conn.executescript(f'''
            CREATE TABLE IF NOT EXISTS pages (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id          TEXT NOT NULL,
                url              TEXT NOT NULL,
                {page_cols_sql},
                scanned_at       TEXT,
                UNIQUE(scan_id, url)
            );
            CREATE TABLE IF NOT EXISTS button_results (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id          TEXT NOT NULL,
                {btn_cols_sql},
                scanned_at       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_pages_scan_id   ON pages(scan_id);
            CREATE INDEX IF NOT EXISTS idx_buttons_scan_id ON button_results(scan_id);
        ''')
        # CREATE TABLE IF NOT EXISTS는 이미 있는 DB 파일엔 새 컬럼을 안 얹어준다 —
        # PAGE_COLUMNS에 필드를 추가해도 예전 fbs_results.db가 자동으로 마이그레이션되게
        # 전체 컬럼을 순회하며 없는 것만 추가한다.
        existing_cols = {row[1] for row in self.conn.execute('PRAGMA table_info(pages)')}
        for name, sql_type, _, _ in self.PAGE_COLUMNS:
            if name not in existing_cols:
                self.conn.execute(f'ALTER TABLE pages ADD COLUMN {name} {sql_type}')
        self.conn.commit()

    def process_item(self, item, spider=None):
        now = datetime.now(timezone.utc).isoformat()

        if isinstance(item, PageItem):
            self._process_page(item, now)
        elif isinstance(item, ButtonResultItem):
            self._process_button(item, now)

        self.conn.commit()
        return item

    def _report_page_defaults(self, url):
        """리포트/집계에 쓰는 인메모리 페이지 dict의 뼈대. PAGE_COLUMNS의 기본값으로
        채워서, item이 어떤 필드를 None으로 비워두거나 아예 안 채웠어도(Item.get()은
        키가 있는데 값이 None이면 default가 안 먹힌다) 이후 집계/정렬이 항상 안전하다."""
        return {'url': url, **{name: default for name, _, _, default in self.PAGE_COLUMNS}}

    def _process_page(self, item, now):
        url = item.get('url')
        if not url:
            return

        if item.get('_fuzz_update'):
            hidden      = json.dumps(item.get('hidden_params', []), ensure_ascii=False)
            hidden_post = json.dumps(item.get('hidden_post_params', []), ensure_ascii=False)
            self.conn.execute(
                'UPDATE pages SET hidden_params=?, hidden_post_params=? WHERE scan_id=? AND url=?',
                (hidden, hidden_post, self._scan_id, url),
            )
            page = self._pages.setdefault(url, self._report_page_defaults(url))
            page['hidden_params']      = item.get('hidden_params', [])
            page['hidden_post_params'] = item.get('hidden_post_params', [])
        else:
            col_names    = ', '.join(name for name, *_ in self.PAGE_COLUMNS)
            placeholders = ', '.join('?' * len(self.PAGE_COLUMNS))
            values = tuple(
                json.dumps(item.get(name), ensure_ascii=False) if is_json else item.get(name)
                for name, _, is_json, _ in self.PAGE_COLUMNS
            )
            self.conn.execute(
                f'''INSERT OR IGNORE INTO pages (scan_id, url, {col_names}, scanned_at)
                    VALUES (?, ?, {placeholders}, ?)''',
                (self._scan_id, url, *values, now),
            )
            page = self._report_page_defaults(url)
            for name, *_ in self.PAGE_COLUMNS:
                val = item.get(name)
                if val is not None:
                    page[name] = val
            self._pages[url] = page

    def _process_button(self, item, now):
        col_names    = ', '.join(name for name, *_ in self.BUTTON_COLUMNS)
        placeholders = ', '.join('?' * len(self.BUTTON_COLUMNS))
        values = tuple(
            json.dumps(item.get(name), ensure_ascii=False) if is_json else item.get(name)
            for name, _, is_json in self.BUTTON_COLUMNS
        )
        self.conn.execute(
            f'''INSERT INTO button_results (scan_id, {col_names}, scanned_at)
                VALUES (?, {placeholders}, ?)''',
            (self._scan_id, *values, now),
        )
        self._button_results.append({name: item.get(name) for name, *_ in self.BUTTON_COLUMNS})

    # ── 리포트 생성 ───────────────────────────────────────────────────────────

    def _write_report(self):
        now    = datetime.now(timezone.utc).isoformat()
        target = self._target_url or (next(iter(self._pages)) if self._pages else 'unknown')
        origin = urlparse(target).netloc or target

        # self._pages의 각 항목은 _report_page_defaults()를 거쳐서만 만들어지므로
        # forms/hidden_params/tech_stack 등은 여기서 항상 실제 값이거나 PAGE_COLUMNS에
        # 정의된 기본값(빈 컨테이너)이지 None이 아니다 — .get()에 default를 또 안 붙여도 안전.
        total_forms        = sum(len(p['forms'])              for p in self._pages.values())
        total_hidden       = sum(len(p['hidden_params'])      for p in self._pages.values())
        total_hidden_post  = sum(len(p['hidden_post_params']) for p in self._pages.values())
        spa_pages          = sum(1 for p in self._pages.values() if p['tech_stack'].get('spa'))
        pages_with_cookies = sum(1 for p in self._pages.values() if p['cookies'])

        pages_sorted = sorted(self._pages.values(), key=lambda p: p['depth'])

        report = {
            'scan_id':    self._scan_id,
            'target':     target,
            'scanned_at': now,
            'summary': {
                'pages_scanned':      len(self._pages),
                'forms_found':        total_forms,
                'hidden_params':      total_hidden,
                'hidden_post_params': total_hidden_post,
                'spa_pages':          spa_pages,
                'pages_with_cookies': pages_with_cookies,
                'button_results':     len(self._button_results),
            },
            'pages':          pages_sorted,
            'button_results': self._button_results,
        }

        report_path = 'scan_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        self._print_page_summaries(pages_sorted)

        print(f"\n{'='*52}")
        print(f"  스캔 완료  : {origin}")
        print(f"  페이지     : {len(self._pages)}")
        print(f"  폼         : {total_forms}  |  숨겨진 파라미터: {total_hidden} (GET) + {total_hidden_post} (POST)")
        print(f"  SPA        : {spa_pages}  |  버튼 결과: {len(self._button_results)}")
        print(f"  리포트     : {report_path}")
        print(f"  DB         : {self.db_path}")
        print(f"{'='*52}\n")

    # ── 페이지 프로필 요약 (크롤 종료 시 일괄) ──────────────────────────────────
    # 어느 경로(정적 크롤/버튼 클릭/SPA)로 찾았든, 모든 페이지가 self._pages에 모인 뒤 여기서
    # 한 번에 요약한다 — 크롤 중 분기마다 따로 찍지 않아 경로에 따라 요약이 빠지는 일이 없다.

    _TECH_FIELDS = [
        ('server',    '웹서버    '),
        ('language',  '언어      '),
        ('framework', '프레임워크'),
        ('cms',       'CMS       '),
        ('spa',       'SPA       '),
        ('session',   '세션쿠키  '),
    ]

    def _print_page_summaries(self, pages_sorted: list) -> None:
        if not pages_sorted:
            return
        print(f"\n# [페이지 요약] {len(pages_sorted)}개 (깊이순)")
        for p in pages_sorted:
            print(f"\n  ── {p.get('method') or 'GET'} {p['url']} "
                  f"(status={p.get('status_code')}, depth={p.get('depth')})")
            self._print_tech(p.get('tech_stack') or {})
            self._print_cookies(p.get('cookies') or [])
            self._print_forms(p.get('forms') or [])
            hidden     = p.get('hidden_params') or []
            hidden_post = [e.get('param') for e in (p.get('hidden_post_params') or [])]
            if hidden or hidden_post:
                print(f"    [숨은 파라미터] GET={hidden or '없음'} | POST={hidden_post or '없음'}")

    def _print_tech(self, tech_stack: dict) -> None:
        print(f"    [기술 스택]")
        for key, label in self._TECH_FIELDS:
            val = tech_stack.get(key)
            marker = '+' if val else '-'
            print(f"      [{marker}] {label}: {val or '없음'}")
        payload = tech_stack.get('session_payload')
        if payload:
            print(f"      [+] 세션 해석    : {payload}")
        for jwt_info in tech_stack.get('jwt_cookies', []):
            print(f"      [+] JWT 쿠키      : {jwt_info['name']} → {jwt_info['payload']}")

    @staticmethod
    def _print_cookies(cookies: list) -> None:
        if not cookies:
            return
        print(f"    [쿠키] {len(cookies)}개")
        for c in cookies:
            flags = c.get('flags') or {}
            on = [k for k in ('httponly', 'secure') if flags.get(k)]
            samesite = f" samesite={flags['samesite']}" if flags.get('samesite') else ''
            tags = (f" ({', '.join(on)}{samesite})" if on or samesite else '')
            print(f"      - {c.get('name')}{tags}")

    @staticmethod
    def _print_forms(forms: list) -> None:
        if not forms:
            return
        print(f"    [폼] {len(forms)}개")
        for i, form in enumerate(forms, 1):
            print(f"      [{i}] {form.get('method')} {form.get('action')} ({form.get('enctype')})")
            for inp in form.get('inputs', []):
                name = inp.get('name') or '(이름없음)'
                print(f"          - {name} [{inp.get('type', 'text')}]")
