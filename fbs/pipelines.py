import sqlite3
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from fbs.items import PageItem, ButtonResultItem


class SQLitePipeline:
    # PageItem 필드 하나를 CREATE TABLE / 마이그레이션 / INSERT / 리포트용 인메모리 dict
    # 네 곳에 따로 반영해야 했던 걸 이 목록 하나로 통합한다. 새 필드를 추가할 땐 여기만
    # 고치면 나머지는 전부 이 목록을 순회해서 생성된다.
    # (컬럼명, SQL 타입, JSON 직렬화 여부, 리포트용 기본값)
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

    def __init__(self, db_path, target_url='', login_id=None, login_pw=None):
        self.db_path     = db_path
        self._target_url = target_url
        self._login_id   = login_id
        self._login_pw   = login_pw

    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            crawler.settings.get('SQLITE_DB_PATH', 'fbs_results.db'),
            crawler.settings.get('TARGET_URL', ''),
            crawler.settings.get('LOGIN_ID', None),
            crawler.settings.get('LOGIN_PW', None),
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
        ).run()

    def _create_tables(self):
        cols_sql = ',\n                '.join(
            f'{name} {sql_type}' for name, sql_type, _, _ in self.PAGE_COLUMNS
        )
        self.conn.executescript(f'''
            CREATE TABLE IF NOT EXISTS pages (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id          TEXT NOT NULL,
                url              TEXT NOT NULL,
                {cols_sql},
                scanned_at       TEXT,
                UNIQUE(scan_id, url)
            );
            CREATE TABLE IF NOT EXISTS button_results (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id                TEXT NOT NULL,
                page_url               TEXT NOT NULL,
                button                 TEXT,
                api_calls              TEXT,
                set_cookies            TEXT,
                response_headers       TEXT,
                cookie_changes         TEXT,
                localstorage_changes   TEXT,
                sessionstorage_changes TEXT,
                dom_changes            TEXT,
                scanned_at             TEXT
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
        self.conn.execute(
            '''INSERT INTO button_results (
                scan_id, page_url, button, api_calls, set_cookies, response_headers,
                cookie_changes, localstorage_changes, sessionstorage_changes,
                dom_changes, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                self._scan_id,
                item.get('page_url'),
                item.get('button'),
                json.dumps(item.get('api_calls'),              ensure_ascii=False),
                json.dumps(item.get('set_cookies'),            ensure_ascii=False),
                json.dumps(item.get('response_headers'),       ensure_ascii=False),
                json.dumps(item.get('cookie_changes'),         ensure_ascii=False),
                json.dumps(item.get('localstorage_changes'),   ensure_ascii=False),
                json.dumps(item.get('sessionstorage_changes'), ensure_ascii=False),
                json.dumps(item.get('dom_changes'),            ensure_ascii=False),
                now,
            ),
        )
        self._button_results.append({
            'page_url':               item.get('page_url'),
            'button':                 item.get('button'),
            'api_calls':              item.get('api_calls', []),
            'set_cookies':            item.get('set_cookies', []),
            'response_headers':       item.get('response_headers', []),
            'cookie_changes':         item.get('cookie_changes', {}),
            'localstorage_changes':   item.get('localstorage_changes', {}),
            'sessionstorage_changes': item.get('sessionstorage_changes', {}),
            'dom_changes':            item.get('dom_changes', []),
        })

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

        print(f"\n{'='*52}")
        print(f"  스캔 완료  : {origin}")
        print(f"  페이지     : {len(self._pages)}")
        print(f"  폼         : {total_forms}  |  숨겨진 파라미터: {total_hidden} (GET) + {total_hidden_post} (POST)")
        print(f"  SPA        : {spa_pages}  |  버튼 결과: {len(self._button_results)}")
        print(f"  리포트     : {report_path}")
        print(f"  DB         : {self.db_path}")
        print(f"{'='*52}\n")
