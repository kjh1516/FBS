import sqlite3
import json
import argparse
from datetime import datetime, timezone

import requests

from fbs.inference.models import AttackSurface, VulnResult
from fbs.inference.profiler import Profiler
from fbs.inference.recon import Recon, DBDetect
from fbs.inference.waf import WafDetector
from fbs.inference.strategies.base import BaseStrategy

"""
이 파일은 추론을 총괄하는 파일입니다.

1. DB에서 데이터 읽기
2. profiler에게 넘겨서 AttackSurface 목록 받기
3. 각 surface를 strategy들에 돌려서 VulnResult 수집 후 저장

을 수행하며, profiler와 strategies를 연결하는 역할을 수행합니다.
"""


# ── 엔진 ──────────────────────────────────────────────────────────────────────

class InferenceEngine:
    def __init__(self, db_path: str = 'fbs_results.db',
                 login_id: str | None = None, login_pw: str | None = None):
        self.db_path   = db_path
        self.login_id  = login_id
        self.login_pw  = login_pw
        self.session   = requests.Session()
        self.profiler  = Profiler()
        self.strategies: list[BaseStrategy] = []
        self._results:   list[VulnResult]   = []

    def _register_strategies(self):
        """구현된 strategy를 순서대로 등록한다."""
        from fbs.inference.strategies.sqli import SQLiStrategy
        from fbs.inference.strategies.xss import XSSStrategy
        # from fbs.inference.strategies.ssti   import SSTIStrategy
        # from fbs.inference.strategies.nosqli import NoSQLiStrategy
        self.strategies = [SQLiStrategy(session=self.session),
                           XSSStrategy(session=self.session)]

    # ── DB 읽기 ───────────────────────────────────────────────────────────────

    def _load_pages(self) -> tuple[list[dict], int]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        scan_id = conn.execute('SELECT MAX(scan_id) FROM pages').fetchone()[0]
        rows = conn.execute(
            'SELECT * FROM pages WHERE scan_id = ?', (scan_id,)
        ).fetchall()
        conn.close()

        pages = []
        for row in rows:
            p = dict(row)
            for key in ('params', 'response_headers', 'cookies',
                        'tech_stack', 'forms', 'hidden_params', 'hidden_post_params',
                        'security_headers'):
                raw = p.get(key)
                if raw:
                    try:
                        p[key] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        pass
            pages.append(p)
        return pages, scan_id

    def _load_button_results(self, scan_id: int) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM button_results WHERE scan_id = ?', (scan_id,)
        ).fetchall()
        conn.close()

        results = []
        for row in rows:
            r = dict(row)
            for key in ('api_calls', 'set_cookies', 'response_headers',
                        'cookie_changes', 'localstorage_changes',
                        'sessionstorage_changes', 'dom_changes'):
                raw = r.get(key)
                if raw:
                    try:
                        r[key] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        pass
            results.append(r)
        return results

    # ── 세션 재사용 ───────────────────────────────────────────────────────────

    def _seed_cookies(self, pages: list[dict]) -> None:
        """크롤링 때 얻은 쿠키를 recon/strategy가 공유하는 requests.Session에 미리 심는다.

        추론 단계는 항상 새 requests.Session()으로 시작한다(self.session = requests.Session()).
        그런데 로그인 진입점이 POST 한 번을 거쳐야만 세션을 발급하는 앱(세션이 없으면
        보호된 페이지가 조용히 다른 곳으로 리다이렉트되는 구조)에서는, 이 새 세션에 아무
        쿠키도 없으면 추론 단계의 모든 요청이 매번 리다이렉트를 따라가 버려서 페이로드가
        실제 취약한 쿼리 근처에도 못 간다 — 실측으로 확인된 문제(로그인 필드에 시간 기반
        SQLi 페이로드를 직접 보내면 9초 넘게 걸리는데, 스캐너를 통하면 항상 즉시 응답).
        Playwright 크롤러는 실제 버튼 클릭 흐름을 그대로 밟아서 필요한 세션을 이미
        발급받아 PageItem에 쿠키로 남겨뒀으므로(scanner.py의 Set-Cookie 수집), 그걸
        그대로 재사용하면 추론 단계도 크롤링 때와 같은 "로그인된/세션 있는" 상태에서
        시작할 수 있다.
        """
        seeded = 0
        for page in pages:
            for c in (page.get('cookies') or []):
                name, value = c.get('name'), c.get('value')
                if name:
                    self.session.cookies.set(name, value or '')
                    seeded += 1
        if seeded:
            print(f"    [세션] 크롤링 때 수집한 쿠키 {seeded}개를 추론 세션에 반영")

    # ── 공유 baseline ─────────────────────────────────────────────────────────

    def _fetch_baselines(self, pages: list[dict]) -> None:
        """페이지마다 파라미터 없이 그냥 GET 한 번 — WafDetector/Recon이 각자 따로
        기본 baseline을 구하던 걸 여기서 한 번만 구해서 page['_baseline']에 저장한다.
        SQLiStrategy는 필드별로 더미값을 채운 별도 baseline이 필요해서 이 공유 baseline과
        다르므로(테스트하는 대상 자체가 다름) 여기 포함하지 않는다."""
        for page in pages:
            url = page.get('url')
            if not url:
                continue
            try:
                resp = self.session.get(url, timeout=10)
                page['_baseline'] = {
                    'status':  resp.status_code,
                    'body':    resp.text,
                    # resp.headers는 requests.structures.CaseInsensitiveDict라
                    # 'ETag'/'etag' 상관없이 조회된다 — dict()로 감싸면 이 성질이
                    # 사라지므로 그대로 들고 있는다 (DB에 다시 저장하지 않아서 안전).
                    'headers': resp.headers,
                    'elapsed': resp.elapsed.total_seconds(),
                }
            except Exception:
                page['_baseline'] = None

    # ── 동적 blind 탐지 ───────────────────────────────────────────────────────

    def _verify_blind(self, surfaces: list[AttackSurface]):
        """recon이 커버하지 못한 표면만 조건부로 반사 프로브한다.

        반사 검사는 recon(DBDetect.probe_reflection) 한 곳으로 통일됐다 — 페이지 표면은
        recon이 이미 쟀고 profiler가 그 측정값으로 blind를 설정하므로 여기선 건드리지 않는다.
        reflection 신호가 없는 표면(버튼 클릭이 캡처한 API 필드 등 recon 미커버)만 같은
        헬퍼로 fallback 프로브해 blind/reflects_html을 채운다. blind = 반사 안 됨."""
        pending = [s for s in surfaces
                   if not s.extra.get('waf_blocked') and s.extra.get('reflection') is None]
        if not pending:
            return  # 모든 표면의 반사를 recon이 이미 측정 — 추가 프로브 불필요
        print(f"\n# [동적 검증] recon 미커버 표면 {len(pending)}개 반사 프로브")
        detector = DBDetect(session=self.session)
        for s in pending:
            data = {p: 'test' for p in (s.extra.get('all_params') or [])}
            refl = detector.probe_reflection(s.url, s.method, data, s.param)
            if refl is None:
                print(f"  SKIP   {s.param} | 요청 실패 또는 WAF 차단")
                continue
            s.extra['reflection'] = refl
            survived = refl.get('survived') or ()
            s.extra['reflects_html'] = bool(
                refl.get('reflected') and '<' in survived and '>' in survived)
            s.blind = not refl.get('reflected')
            print(f"  PROBE  {s.param} | blind={s.blind} ({'blind' if s.blind else 'reflected'})")

    # ── 메인 루프 ─────────────────────────────────────────────────────────────

    def run(self):
        self._register_strategies()

        pages, scan_id = self._load_pages()
        button_results = self._load_button_results(scan_id)

        print(f"\n# [추론 엔진] 페이지 {len(pages)}개 / 버튼 결과 {len(button_results)}개 로드 (scan_id={scan_id})")

        self._seed_cookies(pages)

        # 0단계: 페이지당 baseline(파라미터 없이 그냥 GET) 한 번만 가져와서 공유한다 —
        # 원래 WafDetector와 Recon이 같은 URL을 각자 따로 baseline GET으로 찔러봤는데
        # (WafDetector._fetch, Recon.__default__), 완전히 같은 요청이라 하나로 합쳤다.
        self._fetch_baselines(pages)

        # 1단계: WAF 탐지 — recon보다 먼저, 결과를 page에 실어둔다
        WafDetector(session=self.session).run(pages)

        # 1.5단계: 리콘 — baseline 프로브
        Recon(session=self.session).run(pages)

        # 2단계: 프로파일링 — 공격 표면 추출
        page_surfaces: list[AttackSurface] = []
        for page in pages:
            page_surfaces.extend(self.profiler.profile_page(page))

        print(f"# [프로파일링] 페이지 공격 표면 {len(page_surfaces)}개 추출")
        for i, s in enumerate(page_surfaces, 1):
            hints = s.extra.get('hints', {})
            hints_str = ', '.join(f"{k}({v})" for k, v in hints.items()) if hints else '없음'
            print(f"  [{i}] {s.surface_type} | {s.method} {s.url} | param={s.param} | resp={s.response_type} | hints={hints_str}")
            bd = s.extra.get('breakdown') or {}
            if bd.get('field_matches'):
                fm = ', '.join(f"'{kw}'→{vuln}+{w}" for kw, vuln, w in bd['field_matches'])
                print(f"        └ 필드명 매칭     : {fm}")
            if bd.get('tech_matches'):
                tm = ', '.join(f"{field}={val}→{vuln}+{w}" for field, val, vuln, w in bd['tech_matches'])
                print(f"        └ 기술스택 가중치 : {tm}")
            if bd.get('db_hint') or bd.get('recon_note'):
                note = f" | {bd['recon_note']}" if bd.get('recon_note') else ''
                print(f"        └ recon 신호      : db_hint={bd.get('db_hint')}{note}")
            if bd.get('group_note'):
                print(f"        └ 그룹 신호       : {bd['group_note']}")
            if bd.get('filter_map_note'):
                print(f"        └ 필터 지도 신호  : {bd['filter_map_note']}")

        # 버튼 공격 표면 추출 — 페이지에서 이미 발견된 (url, method, param) 제외
        page_seen = {(s.url, s.method, s.param) for s in page_surfaces}
        btn_surfaces: list[AttackSurface] = []
        print(f"\n# [프로파일링] 버튼 공격 표면 추출")
        for br in button_results:
            for call in (br.get('api_calls') or []):
                for field in (call.get('fields') or []):
                    label = br.get('button', '?')
                    url   = call.get('url', br.get('page_url', ''))
                    method = call.get('method', 'POST').upper()
                    key = (url, method, field)
                    if key in page_seen:
                        print(f"  SKIP (중복) 버튼={label!r} | {method} {url} | param={field}")
                    else:
                        print(f"  ADD          버튼={label!r} | {method} {url} | param={field}")
            btn_surfaces.extend(self.profiler.profile_button(br, pages=pages))

        btn_surfaces = [s for s in btn_surfaces if (s.url, s.method, s.param) not in page_seen]

        surfaces = page_surfaces + btn_surfaces
        for s in surfaces:
            s.login_id = self.login_id
            s.login_pw = self.login_pw
        print(f"\n# [프로파일링] 최종 공격 표면 {len(surfaces)}개 (페이지 {len(page_surfaces)} + 버튼 {len(btn_surfaces)})")
        if self.login_id:
            print(f"# [크리덴셜] login_id={self.login_id!r} 주입 완료")

        # 3단계: 동적 검증 — 캐너리 프로브로 blind 확정
        self._verify_blind(surfaces)

        if not surfaces:
            print("# [추론 엔진] 공격 표면 없음 — 종료")
            return

        if not self.strategies:
            print("# [추론 엔진] 등록된 strategy 없음 — 종료")
            return

        # 4단계: 각 전략이 내부적으로 probe → analyze → reattack 수행
        #
        # hidden_param(퍼징으로 발견된 숨겨진 파라미터)을 다른 surface보다 먼저 처리한다 —
        # HTML에 그냥 보이는 일반 필드와 달리, hidden_param은 존재조차 숨겨져 있었는데도
        # 퍼징이 응답 변화를 실제로 확인해서 찾아낸 값이라 그 자체가 이미 "뭔가 있다"는 강한
        # 사전 신호다. 점수(hints)로 어떤 strategy를 돌릴지 정하는 기존 로직(can_handle)은
        # 그대로 두고, 정렬은 hidden_param 여부만 기준으로 한다 — 안정 정렬(stable sort)이라
        # hidden_param끼리·나머지끼리는 원래 순서(페이지/폼 등장 순서) 그대로 유지된다.
        surfaces = sorted(surfaces, key=lambda s: s.surface_type != 'hidden_param')
        hidden_count = sum(1 for s in surfaces if s.surface_type == 'hidden_param')
        if hidden_count:
            print(f"# [우선순위] hidden_param {hidden_count}개를 다른 공격 표면보다 먼저 처리하도록 재정렬")

        print(f"\n# [추론 시작] strategy {len(self.strategies)}개 실행\n")
        for i, surface in enumerate(surfaces, 1):
            print(f"  [{i}/{len(surfaces)}] {surface.surface_type} | {surface.method} {surface.url} | param={surface.param}")

            # 이 표면을 처리할 수 있는 전략들 중 '우선순위(profiler hint 점수)가 가장 높은 하나'만
            # 실행한다 — 한 필드에 SQLi·XSS 등 여러 전략을 전부 돌리지 않는다. 프로파일링이 가장
            # 유력하다고 본 유형이 이기고, 나머지는 스킵한다(예: username은 sqli 0.8 > xss 0.4라
            # SQLi만 실행). 동점이면 등록 순서(안정 정렬)로 앞선 전략이 이긴다.
            applicable = [s for s in self.strategies if s.can_handle(surface)]
            if not applicable:
                continue
            strategy = max(applicable, key=lambda s: s.priority(surface))
            skipped = [s.__class__.__name__ for s in applicable if s is not strategy]
            skip_note = f" (스킵: {', '.join(skipped)})" if skipped else ""
            print(f"    → {strategy.__class__.__name__} 실행 중 (우선순위 {strategy.priority(surface):.2f}){skip_note}...")

            results = strategy.run(surface)
            if results:
                for r in results:
                    print(f"    ══ 최종 취약점 확정 ═══════════════════════════")
                    print(f"    [{r.severity}] {r.vuln_type} | payload=\"{r.payload}\"")
                    print(f"    근거   : {r.evidence}")
                    impact = (r.detail or {}).get('cookie_impact')
                    if impact and impact.get('verdict'):
                        print(f"    임팩트 : {impact['verdict']}")
                    print(f"    ═══════════════════════════════════════════════")
            else:
                print(f"    · 취약점 없음")
            self._results.extend(results)

        self._write_results()

    # ── 결과 저장 ─────────────────────────────────────────────────────────────

    def _write_results(self):
        now = datetime.now(timezone.utc).isoformat()

        if not self._results:
            print("\n# [추론 엔진] 발견된 취약점 없음")
            return

        _SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
        sorted_results = sorted(
            self._results,
            key=lambda r: _SEVERITY_ORDER.get(r.severity, 99),
        )

        report = {
            'scanned_at': now,
            'total':      len(sorted_results),
            'vulnerabilities': [
                {
                    'vuln_type':    r.vuln_type,
                    'severity':     r.severity,
                    'url':          r.surface.url,
                    'param':        r.surface.param,
                    'method':       r.surface.method,
                    'surface_type': r.surface.surface_type,
                    'payload':      r.payload,
                    'evidence':     r.evidence,
                    'detail':       r.detail,
                }
                for r in sorted_results
            ],
        }

        out_path = 'vuln_report.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        counts = {}
        for r in sorted_results:
            counts[r.severity] = counts.get(r.severity, 0) + 1

        print(f"\n{'='*52}")
        print(f"  취약점 발견  : {len(sorted_results)}개")
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
            if counts.get(sev):
                print(f"  {sev:8s}   : {counts[sev]}")
        print(f"  리포트       : {out_path}")
        print(f"{'='*52}\n")


# ── 단독 실행 진입점 ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='FBS 추론 엔진 단독 실행')
    parser.add_argument('--db',       default='fbs_results.db', help='SQLite DB 경로')
    parser.add_argument('--login-id', default=None,             help='로그인 아이디')
    parser.add_argument('--login-pw', default=None,             help='로그인 비밀번호')
    args = parser.parse_args()

    InferenceEngine(db_path=args.db, login_id=args.login_id, login_pw=args.login_pw).run()


if __name__ == '__main__':
    main()
