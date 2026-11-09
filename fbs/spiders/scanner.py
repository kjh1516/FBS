import os
import sys
import uuid
import json as _json
import scrapy
from scrapy.spiders import CrawlSpider
from urllib.parse import urlparse, urljoin, parse_qs
from fbs.utils import detect_tech_stack, header_decode, is_jwt, decode_jwt_payload
from fbs.items import PageItem, ButtonResultItem
from fbs.inference.validation import classify_waf_block, EVASION_TRANSFORMS
from fbs.inference.compare import visible_text, diff_score
from scrapy_playwright.page import PageMethod

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

FUZZ_MARKER = "john17823"
BLOCK_SIZE   = 45
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'params.txt')

# POST 폼 퍼징 진단용 probe 값 3종 (자세한 전략은 _fuzz_post_params 문서 참고).
# "9 '"는 숫자 컨텍스트/문자열 컨텍스트 둘 다 깨뜨릴 수 있는 값이라 1순위로 시도하고,
# 앱 자체 필터(sqli_filter류)에 막히면 우회를 먼저 시도한 뒤, 그래도 안 되면 특수문자
# 없이 "타입 불일치"만으로 에러를 유발하는 숫자/문자열 두 값으로 나눠서 재시도한다.
POST_PROBE_AGGRESSIVE = "9 '"
POST_PROBE_NUMERIC    = "9"
POST_PROBE_ALPHA      = "abc"
DIFF_SCORE_THRESHOLD  = 5

_BTN_DANGER_KW = frozenset([
    'delete', 'remove', 'logout', 'signout', 'sign-out', 'cancel',
    'purchase', 'pay', 'checkout', 'unsubscribe', 'reset', 'clear',
    '삭제', '제거', '로그아웃', '취소', '결제', '구매', '초기화', '탈퇴',
])

_SKIP_EXTENSIONS = frozenset([
    'pdf', 'zip', 'exe', 'jpg', 'jpeg', 'png', 'gif',
    'svg', 'ico', 'woff', 'woff2', 'ttf', 'mp4', 'mp3',
])


class ScannerSpider(CrawlSpider):
    name = "scanner"

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        spider = super().from_crawler(crawler, *args, **kwargs)
        crawler.settings.set('TARGET_URL', spider.target_url, priority='spider')
        crawler.settings.set('LOGIN_ID',   spider.login_id,   priority='spider')
        crawler.settings.set('LOGIN_PW',   spider.login_pw,   priority='spider')
        return spider

    def __init__(self, target_url=None, login_id=None, login_pw=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not target_url:
            raise ValueError("target_url is required")

        self.start_urls  = [target_url]
        self.target_url  = target_url
        self.login_id    = login_id
        self.login_pw    = login_pw
        parsed = urlparse(target_url)
        self.allowed_domains = [parsed.hostname]

        self.rules = ()
        self._compile_rules()

        # 퍼징 wordlist 로딩
        wordlist_path = kwargs.pop('wordlist', DEFAULT_WORDLIST)
        self._param_wordlist = self._load_wordlist(wordlist_path)
        self._fuzzed_urls         = set()
        self._fuzzed_post_forms   = set()
        self._processed_urls      = set()
        self._btn_discovered_urls = set()
        self._login_done          = False
        self._playwright_cookies  = None  # 로그인 성공 후 설정, Playwright context에 주입

        # 수집 정보 저장소
        self.discovery = {
            'robots': {
                'found': False,
                'disallow': [],
                'sitemap_links': [],
            },
            'sitemap': {
                'found': False,
                'urls': [],
            },
        }

    async def start(self):
        parsed = urlparse(self.start_urls[0])
        root = f"{parsed.scheme}://{parsed.netloc}"

        yield scrapy.Request(urljoin(root, '/robots.txt'),
                             callback=self.parse_robots,
                             errback=self.ignore_error,
                             dont_filter=True)

        yield scrapy.Request(urljoin(root, '/sitemap.xml'),
                             callback=self.parse_sitemap,
                             errback=self.ignore_error,
                             dont_filter=True)

        yield scrapy.Request(self.start_urls[0],
                             callback=self.parse_item,
                             dont_filter=True)

    def _do_login(self, response):
        """parse_item에서 로그인 폼 발견 시 크리덴셜을 제출한다."""
        login_form = None
        for form in response.css('form'):
            if form.css('input[type="password"]'):
                login_form = form
                break

        if login_form is None:
            return

        self._login_done = True
        action  = login_form.attrib.get('action') or response.url
        method  = login_form.attrib.get('method', 'POST').upper()
        enctype = login_form.attrib.get('enctype', 'application/x-www-form-urlencoded')

        formdata = {}
        for inp in login_form.css('input'):
            name  = inp.attrib.get('name')
            if not name:
                continue
            itype = inp.attrib.get('type', 'text').lower()
            if itype == 'password':
                formdata[name] = self.login_pw
            elif itype in ('text', 'email', 'tel', ''):
                formdata[name] = self.login_id
            elif itype == 'hidden':
                formdata[name] = inp.attrib.get('value', '')

        print(f"# [로그인] {method} {action} | fields={list(formdata.keys())}")

        def after_login(r):
            has_login_form = bool(r.css('input[type="password"]'))
            if has_login_form:
                print(f"# [로그인] 실패 — 로그인 폼이 남아있음")
            else:
                print(f"# [로그인] 성공")
                raw = r.request.headers.get('Cookie', b'')
                if isinstance(raw, bytes):
                    raw = raw.decode('utf-8', errors='replace')
                domain = urlparse(self.start_urls[0]).hostname
                self._playwright_cookies = [
                    {'name': n.strip(), 'value': v.strip(), 'domain': domain, 'path': '/'}
                    for part in raw.split(';')
                    if '=' in part
                    for n, _, v in [part.strip().partition('=')]
                ]
            yield from self.parse_item(r)

        if 'application/json' in enctype:
            yield scrapy.Request(
                action, method=method,
                body=_json.dumps(formdata),
                headers={'Content-Type': 'application/json'},
                callback=after_login, dont_filter=True,
            )
        else:
            from scrapy import FormRequest
            yield FormRequest(
                action, method=method,
                formdata=formdata,
                callback=after_login, dont_filter=True,
            )

    def ignore_error(self, failure):
        url = failure.request.url
        if '/robots.txt' in url:
            print(f"\n# [robots.txt] 없음")
        elif '/sitemap' in url:
            print(f"\n# [sitemap] 없음")
        elif failure.request.meta.get('is_fuzz'):
            print(f"    [퍼징 요청 실패] {url} — {failure.value!r} (콜백 미도달, 이 시도는 스킵됨)")

    def parse_robots(self, response):
        if response.status != 200:
            print(f"\n# [robots.txt] {response.status} — 없음")
            return

        print(f"\n# [robots.txt] 발견 — {response.url}")
        parsed = urlparse(self.start_urls[0])
        root = f"{parsed.scheme}://{parsed.netloc}"

        for line in response.text.splitlines():
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if not path or path == '/':
                    continue
                url = urljoin(root, path)
                self.discovery['robots']['disallow'].append(url)
                print(f"    [+] Disallow: {url}")

            elif line.lower().startswith('sitemap:'):
                sitemap_url = line[line.index(':') + 1:].strip()
                self.discovery['robots']['sitemap_links'].append(sitemap_url)
                print(f"    [+] Sitemap 링크: {sitemap_url}")
                yield scrapy.Request(sitemap_url,
                                     callback=self.parse_sitemap,
                                     errback=self.ignore_error)

        self.discovery['robots']['found'] = True

    def parse_sitemap(self, response):
        if response.status != 200:
            print(f"\n# [sitemap] {response.status} — 없음")
            return

        print(f"\n# [sitemap] 발견 — {response.url}")
        self.discovery['sitemap']['found'] = True

        for sitemap_url in response.xpath('//sitemap/loc/text()').getall():
            print(f"    [+] 하위 sitemap: {sitemap_url}")
            yield scrapy.Request(sitemap_url,
                                 callback=self.parse_sitemap,
                                 errback=self.ignore_error)

        for url in response.xpath('//url/loc/text()').getall():
            self.discovery['sitemap']['urls'].append(url)
            print(f"    [+] URL: {url}")

    @staticmethod
    def _new_page_item(url, response, depth):
        """PageItem 골격을 만든다. tech_stack/hidden_params/hidden_post_params을 None으로
        비워두면 파이프라인의 _write_report()가 p.get(key, default)처럼 "키가 없을 때만"
        기본값이 적용되는 패턴을 쓰고 있어서(키는 있는데 값이 None이면 기본값이 안 먹힘)
        리포트 생성 단계에서 AttributeError로 죽는다 — 항상 빈 컨테이너로 명시 초기화한다."""
        item = PageItem()
        item['url']          = url
        item['status_code']  = response.status
        item['content_type'] = header_decode(response.headers.get('Content-Type', b''))
        item['depth']        = depth
        item['method']       = response.request.method
        item['params']       = parse_qs(urlparse(url).query)
        item['tech_stack']         = {}
        item['hidden_params']      = []
        item['hidden_post_params'] = []
        item['_fuzz_update']       = False
        return item

    @staticmethod
    def _collect_cookies(response):
        """Set-Cookie 응답 헤더 + 현재 요청이 실제로 보낸 Cookie 헤더를 합쳐 쿠키 목록을
        만든다. 세션이 POST 한 번으로만 발급되는 앱(예: 로그인 진입점이 세션 없으면
        리다이렉트되는 구조)에서는, 세션을 발급받은 그 응답 자체가 아니라 그 이후에
        도달한 페이지의 응답에서는 Set-Cookie가 다시 안 찍힌다(Flask는 세션이 안
        바뀌면 재전송 안 함) — 그래서 이 응답 자체의 Set-Cookie만 보면 세션 쿠키를
        놓친다. request Cookie 헤더는 Scrapy/브라우저가 지금 이 요청에 실제로 실어
        보낸 쿠키라, 이전 홉에서 받은 세션 쿠키도 여기 그대로 남아있어 놓치지 않는다.
        """
        cookies = []
        seen_names = set()
        for raw in response.headers.getlist('Set-Cookie'):
            cookie_str = header_decode(raw)
            parts      = [p.strip() for p in cookie_str.split(';')]
            nv         = parts[0].split('=', 1)
            name       = nv[0].strip()
            value      = nv[1].strip() if len(nv) > 1 else ''
            attrs_lower = [p.lower() for p in parts[1:]]
            samesite = next(
                (p.split('=', 1)[1].strip() for p in parts[1:] if p.lower().startswith('samesite=')),
                None,
            )
            cookies.append({
                'name':  name,
                'value': value,
                'raw':   cookie_str,
                'flags': {
                    'httponly': any('httponly' in a for a in attrs_lower),
                    'secure':   any(a.strip() == 'secure' for a in attrs_lower),
                    'samesite': samesite,
                },
            })
            seen_names.add(name)

        req_cookie = response.request.headers.get('Cookie', b'')
        if isinstance(req_cookie, bytes):
            req_cookie = req_cookie.decode('utf-8', errors='replace')
        for pair in req_cookie.split(';'):
            pair = pair.strip()
            if '=' not in pair:
                continue
            n, _, v = pair.partition('=')
            n = n.strip()
            if n and n not in seen_names:
                cookies.append({
                    'name':  n,
                    'value': v.strip(),
                    'raw':   pair,
                    'flags': {'httponly': None, 'secure': None, 'samesite': None},
                })
        return cookies

    def parse_item(self, response):
        if response.url in self._processed_urls:
            return
        self._processed_urls.add(response.url)

        print(f"\n{'─'*60}")
        print(f"  {response.status} {response.request.method} {response.url}")
        print(f"{'─'*60}")
        item = self._new_page_item(response.url, response, response.meta.get('depth', 0))

        # 응답 헤더 수집
        response_headers = {}
        for key, values in response.headers.items():
            name = header_decode(key)
            response_headers[name] = [header_decode(v) for v in
                                      (values if isinstance(values, list) else [values])]
        item['response_headers'] = response_headers

        # 보안 헤더 점검
        _SECURITY_HEADERS = [
            'X-Frame-Options', 'Content-Security-Policy',
            'Strict-Transport-Security', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy',
        ]
        security_headers = {}
        for h in _SECURITY_HEADERS:
            val = response.headers.get(h)
            security_headers[h] = {
                'present': val is not None,
                'value':   header_decode(val) if val is not None else None,
            }
        meta_csp = response.css('meta[http-equiv="Content-Security-Policy"]::attr(content)').get()
        if meta_csp:
            security_headers['Content-Security-Policy-Meta'] = {
                'present': True,
                'value':   meta_csp,
            }
        item['security_headers'] = security_headers

        cookies = self._collect_cookies(response)
        item['cookies'] = cookies

        # 기술 스택 탐지
        script_srcs = response.css('script::attr(src)').getall()
        tech_stack = detect_tech_stack(
            response_headers, cookies, response.text, response.url, script_srcs
        )
        item['tech_stack'] = tech_stack

        # 정적 폼 수집
        forms = []
        for form in response.css('form'):
            action  = response.urljoin(form.attrib.get('action', ''))
            method  = form.attrib.get('method', 'get').upper()
            enctype = form.attrib.get('enctype', 'application/x-www-form-urlencoded').lower()
            inputs  = []

            for tag in form.css('input'):
                inputs.append({
                    'name':  tag.attrib.get('name'),
                    'type':  tag.attrib.get('type', 'text'),
                    'value': tag.attrib.get('value', ''),
                })
            for tag in form.css('select'):
                inputs.append({
                    'name':    tag.attrib.get('name'),
                    'type':    'select',
                    'options': tag.css('option::attr(value)').getall(),
                })
            for tag in form.css('textarea'):
                inputs.append({
                    'name': tag.attrib.get('name'),
                    'type': 'textarea',
                })

            form_data = {'action': action, 'method': method, 'enctype': enctype, 'inputs': inputs}
            expanded  = self._expand_json_proxy_form(form_data, response.url)
            if expanded:
                forms.extend(expanded)
            else:
                forms.append(form_data)

        item['forms']         = forms

        # a 태그 링크 수집 (URL 중복 제거)
        start_host = urlparse(self.start_urls[0]).hostname
        seen_urls = set()
        links = []
        for a in response.css('a[href]'):
            href = response.urljoin(a.attrib['href'])
            if href in seen_urls:
                continue
            seen_urls.add(href)
            text = (a.css('::text').get() or '').strip()
            parsed_href = urlparse(href)
            links.append({
                'url':      href,
                'text':     text,
                'internal': parsed_href.hostname == start_host,
            })
        item['links']         = links

        # 내부 링크 스캔 요청 (Scrapy 중복 필터 + _processed_urls로 재방문 방지)
        for link in links:
            if not link['internal'] or link['url'] in self._processed_urls:
                continue
            ext = link['url'].rsplit('.', 1)[-1].split('?')[0].lower()
            if ext in _SKIP_EXTENSIONS:
                continue
            yield scrapy.Request(link['url'], callback=self.parse_item,
                                 errback=self.ignore_error)

        self._print_tech_stack(tech_stack)
        self._print_forms(forms)
        self._print_links(links)

        if tech_stack.get('spa'):
            api_calls = []
            yield scrapy.Request(
                response.url,
                callback=self.parse_playwright_rendered,
                errback=self.ignore_error,
                dont_filter=True,
                meta={
                    'playwright': True,
                    'playwright_page_event_handlers': {'request': self._make_api_interceptor(api_calls)},
                    'captured_api_calls': api_calls,
                    'playwright_render_mode': 'spa_supplement',
                    'spa_name': tech_stack['spa'],
                    'partial_item': item,
                    'existing_forms': list(forms),
                },
            )
            return

        yield item

        form_params = {inp['name'] for f in forms for inp in f['inputs'] if inp.get('name')}
        known_params = set(item['params'].keys()) | form_params
        yield from self._fuzz_get_params(response, known_params, item)
        for form in forms:
            if form['method'] == 'POST':
                yield from self._fuzz_post_params(form, item)
        yield from self._schedule_button_clicks(response.url)

        if self.login_id and self.login_pw and not self._login_done:
            yield from self._do_login(response)

    @staticmethod
    def _print_forms(forms: list):
        if not forms:
            return
        print(f"\n# [폼 발견] {len(forms)}개")
        for i, form in enumerate(forms, 1):
            print(f"    [{i}] {form['method']} {form['action']} ({form['enctype']})")
            for inp in form['inputs']:
                name = inp.get('name') or '(이름없음)'
                typ  = inp.get('type', 'text')
                print(f"        - {name} [{typ}]")

    @staticmethod
    def _print_links(links: list):
        if not links:
            return
        internal = [l for l in links if l['internal']]
        external = [l for l in links if not l['internal']]
        print(f"\n# [링크 발견] 내부 {len(internal)}개, 외부 {len(external)}개")
        for l in internal[:10]:
            label = l['text'] or '(텍스트 없음)'
            print(f"    [+] {label[:40]!r} → {l['url']}")
        if len(internal) > 10:
            print(f"    ... 외 내부 {len(internal) - 10}개")

    _BTN_DISCOVER_JS = '''() => {
        const sel = 'button:not([disabled]), input[type="submit"]:not([disabled]), input[type="button"]:not([disabled])';
        return [...document.querySelectorAll(sel)].map(el => ({
            text:       (el.textContent || '').trim(),
            value:      el.value || '',
            id:         el.id || '',
            name:       el.name || '',
            ariaLabel:  el.getAttribute('aria-label') || '',
            form_action: (el.form && el.form.action) || ''
        }));
    }'''

    # ── JSON 프록시 폼 탐지 ───────────────────────────────────────────────────

    def _expand_json_proxy_form(self, form_data, base_url):
        proxy_action = form_data.get('action', base_url)
        expanded = []

        for inp in form_data.get('inputs', []):
            if inp.get('type') != 'hidden':
                continue
            raw_val = inp.get('value', '')
            if not raw_val or not raw_val.strip().startswith('{'):
                continue
            try:
                descriptor = _json.loads(raw_val)
            except (ValueError, TypeError):
                continue
            if not isinstance(descriptor, dict):
                continue

            path   = descriptor.get('path') or descriptor.get('url') or descriptor.get('endpoint')
            method = descriptor.get('method', 'POST').upper()
            body   = descriptor.get('body') or descriptor.get('data') or descriptor.get('params')

            if not path or not isinstance(body, dict):
                continue

            inner_inputs = [{'name': k, 'type': 'text'} for k in body]
            if not inner_inputs:
                continue

            proxy_path = urlparse(proxy_action).path
            print(f"    [+] JSON 프록시 폼 감지: {inp['name']} → {method} {path} "
                  f"/ 필드: {list(body.keys())} ({proxy_path} 경유)")
            expanded.append({
                'action':         proxy_action,
                'method':         form_data.get('method', 'POST').upper(),
                'enctype':        form_data.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs':         inner_inputs,
                'proxy_field':    inp['name'],
                'proxy_template': descriptor,
            })

        return expanded if expanded else None

    # ── 버튼 클릭 스캔 ────────────────────────────────────────────────────────

    def _playwright_meta(self) -> dict:
        """로그인 여부에 따라 Playwright context 메타를 반환한다."""
        if self._playwright_cookies:
            return {
                'playwright': True,
                'playwright_context': 'authenticated',
                'playwright_context_kwargs': {
                    'storage_state': {'cookies': self._playwright_cookies}
                },
            }
        return {'playwright': True}

    def _schedule_button_clicks(self, url, depth=0, already_clicked=None):
        discover_pm = PageMethod('evaluate', self._BTN_DISCOVER_JS)
        pw_meta = self._playwright_meta()
        yield scrapy.Request(
            url,
            callback=self._discover_buttons_callback,
            errback=self.ignore_error,
            dont_filter=True,
            meta={
                **pw_meta,
                'playwright_page_methods': [
                    PageMethod('wait_for_load_state', 'networkidle'),
                    discover_pm,
                ],
                'btn_discover_pm':     discover_pm,
                'btn_page_url':        url,
                'btn_depth':           depth,
                'btn_already_clicked': frozenset(already_clicked or []),
            },
        )

    def _discover_buttons_callback(self, response):
        page_url        = response.url  # 리디렉션 후 실제 렌더링된 URL 사용
        discover_pm     = response.meta.get('btn_discover_pm')
        depth           = response.meta.get('btn_depth', 0)

        if depth == 0:
            if page_url in self._btn_discovered_urls:
                return
            self._btn_discovered_urls.add(page_url)
        already_clicked = response.meta.get('btn_already_clicked', frozenset())
        raw_buttons     = discover_pm.result or []

        # 버튼 클릭(또는 리다이렉트)으로만 도달하는 페이지는 정적 크롤(parse_item)이
        # 한 번도 못 보고 지나갈 수 있다 — 그러면 그 페이지의 폼/필드 퍼징이 통째로
        # 스킵된다(실측: /에서 버튼 눌러 /login에 도달했는데 login 폼이 전혀 스캔 안 됨).
        # parse_playwright_rendered(SPA 경로)가 이미 쓰는 것과 같은 패턴 — 렌더링된
        # HTML에서 폼을 뽑아 즉시 퍼징한다. _fuzz_get_params/_fuzz_post_params 내부에
        # 이미 URL/폼 action 단위 중복 방지가 있어서, 이 URL이 parse_item으로도 이미
        # 방문됐었다면 여기선 조용히 스킵되니 매번 호출해도 안전하다.
        item = self._new_page_item(page_url, response, depth)
        # 버튼 클릭(예: "로그인 페이지로 이동")이 세션을 발급하는 POST를 거쳤을 수 있다 —
        # 그 세션 쿠키를 여기서 안 챙기면 추론 단계가 재사용할 쿠키가 없어서, 세션 필요한
        # 페이지(예: /login)에 대한 이후 페이로드가 전부 조용히 리다이렉트당한다(실측 확인).
        item['cookies'] = self._collect_cookies(response)
        forms = self._extract_forms_from_rendered(response.text, page_url)
        item['forms'] = forms
        yield item

        if forms:
            self._print_forms(forms)
            form_params  = {inp['name'] for f in forms for inp in f['inputs'] if inp.get('name')}
            known_params = set(item['params'].keys()) | form_params
            yield from self._fuzz_get_params(response, known_params, item)
            for form in forms:
                if form['method'] == 'POST':
                    yield from self._fuzz_post_params(form, item)

        safe = []
        seen = set()
        for btn in raw_buttons:
            text  = btn.get('text', '')
            value = btn.get('value', '')
            aria  = btn.get('ariaLabel', '')
            bid   = btn.get('id', '')
            name  = btn.get('name', '')
            label = text or value or aria or bid or name or f"submit@{btn.get('form_action', 'unknown')}"
            if label in seen or label in already_clicked:
                continue
            combined = ' '.join(filter(None, [text, value, aria, bid, name])).lower()
            if any(kw in combined for kw in _BTN_DANGER_KW):
                matched = [kw for kw in _BTN_DANGER_KW if kw in combined]
                print(f"    [-] [버튼] 위험 키워드 필터 — {label!r} ({matched})")
                continue
            seen.add(label)
            safe.append({'label': label, 'id': bid, 'text': text, 'value': value})

        if not safe:
            if raw_buttons:
                print(f"\n# [버튼 탐색] {page_url} — {len(raw_buttons)}개 발견, 모두 필터됨")
            return

        depth_tag = f" (재탐색 {depth}단계)" if depth > 0 else ""
        print(f"\n# [버튼 탐색] {page_url}{depth_tag} — {len(safe)}개 안전 버튼")
        for btn in safe:
            print(f"    [+] {btn['label']!r}")

        _STORAGE_JS = '''() => {
            try {
                const ls = {}, ss = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i); ls[k] = localStorage.getItem(k);
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k);
                }
                return JSON.stringify({ls, ss});
            } catch(e) { return '{"ls":{},"ss":{}}'; }
        }'''

        all_safe_labels = frozenset(btn['label'] for btn in safe)
        for btn in safe:
            if btn['id']:
                click_js = f"() => {{ const el = document.getElementById({_json.dumps(btn['id'])}); if (el) el.click(); }}"
            elif btn['text'] or btn['value']:
                needle = _json.dumps(btn['text'] or btn['value'])
                click_js = (
                    f"() => {{ const all = [...document.querySelectorAll("
                    f"'button, input[type=\"submit\"], input[type=\"button\"]')];"
                    f" const el = all.find(b => (b.textContent || b.value || '').trim().includes({needle}));"
                    f" if (el) el.click(); }}"
                )
            else:
                continue

            api_calls       = []
            session_changes = {'set_cookies': [], 'response_headers': []}
            before_pm         = PageMethod('evaluate', '() => document.body.innerText')
            after_pm          = PageMethod('evaluate', '() => document.body.innerText')
            before_cookie_pm  = PageMethod('evaluate', '() => document.cookie')
            after_cookie_pm   = PageMethod('evaluate', '() => document.cookie')
            before_storage_pm = PageMethod('evaluate', _STORAGE_JS)
            after_storage_pm  = PageMethod('evaluate', _STORAGE_JS)
            pw_meta = self._playwright_meta()
            yield scrapy.Request(
                page_url,
                callback=self._parse_button_click_result,
                errback=self.ignore_error,
                dont_filter=True,
                meta={
                    **pw_meta,
                    'playwright_page_event_handlers': {
                        'request':  self._make_api_interceptor(api_calls),
                        'response': self._make_response_interceptor(session_changes),
                    },
                    'playwright_page_methods': [
                        PageMethod('wait_for_load_state', 'networkidle'),
                        before_pm,
                        before_cookie_pm,
                        before_storage_pm,
                        PageMethod('evaluate', click_js),
                        PageMethod('wait_for_timeout', 1500),
                        after_pm,
                        after_cookie_pm,
                        after_storage_pm,
                    ],
                    'captured_api_calls':     api_calls,
                    'captured_session':       session_changes,
                    'btn_before_pm':          before_pm,
                    'btn_after_pm':           after_pm,
                    'btn_before_cookie_pm':   before_cookie_pm,
                    'btn_after_cookie_pm':    after_cookie_pm,
                    'btn_before_storage_pm':  before_storage_pm,
                    'btn_after_storage_pm':   after_storage_pm,
                    'btn_label':              btn['label'],
                    'btn_page_url':           page_url,
                    'btn_depth':              depth,
                    'btn_already_clicked':    already_clicked | all_safe_labels,
                },
            )

    @staticmethod
    def _make_response_interceptor(session_changes: dict):
        _AUTH_HEADERS = frozenset([
            'set-cookie', 'x-session-id', 'x-token', 'authorization',
            'x-auth-token', 'x-csrf-token', 'x-access-token',
        ])

        def handle(response):
            url_lower = response.url.lower()
            if any(url_lower.endswith(ext) for ext in
                   ('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ico')):
                return
            headers = response.headers
            sc = headers.get('set-cookie', '')
            if sc:
                session_changes['set_cookies'].append({'url': response.url, 'raw': sc})
            for h in _AUTH_HEADERS - {'set-cookie'}:
                val = headers.get(h, '')
                if val:
                    session_changes['response_headers'].append(
                        {'url': response.url, 'header': h, 'value': val}
                    )

        return handle

    def _parse_button_click_result(self, response):
        page_url        = response.meta.get('btn_page_url', response.url)
        label           = response.meta.get('btn_label', '?')
        depth           = response.meta.get('btn_depth', 0)
        api_calls       = response.meta.get('captured_api_calls', [])
        session_changes = response.meta.get('captured_session', {})
        before_pm         = response.meta.get('btn_before_pm')
        after_pm          = response.meta.get('btn_after_pm')
        before_cookie_pm  = response.meta.get('btn_before_cookie_pm')
        after_cookie_pm   = response.meta.get('btn_after_cookie_pm')
        before_storage_pm = response.meta.get('btn_before_storage_pm')
        after_storage_pm  = response.meta.get('btn_after_storage_pm')

        before_text = (before_pm.result or '') if before_pm else ''
        after_text  = (after_pm.result  or '') if after_pm  else ''
        new_lines   = [
            l.strip() for l in after_text.splitlines()
            if l.strip() and l not in set(before_text.splitlines())
        ]

        def _parse_cookie_str(s):
            out = {}
            for part in (s or '').split(';'):
                part = part.strip()
                if '=' in part:
                    k, _, v = part.partition('=')
                    out[k.strip()] = v.strip()
            return out

        before_cookies  = _parse_cookie_str((before_cookie_pm.result or '') if before_cookie_pm else '')
        after_cookies   = _parse_cookie_str((after_cookie_pm.result  or '') if after_cookie_pm  else '')
        changed_cookies = {
            k: {'before': before_cookies.get(k), 'after': v}
            for k, v in after_cookies.items()
            if before_cookies.get(k) != v
        }

        def _parse_storage(pm):
            try:
                raw = (pm.result or '{"ls":{},"ss":{}}') if pm else '{"ls":{},"ss":{}}'
                return _json.loads(raw)
            except Exception:
                return {'ls': {}, 'ss': {}}

        before_storage = _parse_storage(before_storage_pm)
        after_storage  = _parse_storage(after_storage_pm)
        changed_ls = {k: v for k, v in after_storage['ls'].items()
                      if before_storage['ls'].get(k) != v}
        changed_ss = {k: v for k, v in after_storage['ss'].items()
                      if before_storage['ss'].get(k) != v}

        set_cookies  = session_changes.get('set_cookies', [])
        resp_headers = session_changes.get('response_headers', [])

        has_changes = any([api_calls, new_lines, changed_cookies,
                           changed_ls, changed_ss, set_cookies, resp_headers])
        if not has_changes:
            return

        print(f"\n# [버튼 클릭 결과] {page_url} — 버튼: {label!r}")
        if api_calls:
            print(f"  [네트워크]")
            for call in api_calls:
                print(f"    [+] {call['method']} {call['url']}")
                if call.get('fields'):
                    print(f"    [>] 필드: {call['fields']}")
        if set_cookies:
            print(f"  [Set-Cookie]")
            for sc in set_cookies:
                print(f"    [+] {sc['url']}\n    [>] {sc['raw'][:200]}")
        if resp_headers:
            print(f"  [응답 헤더]")
            for rh in resp_headers:
                print(f"    [+] {rh['header']}: {rh['value'][:200]}  ({rh['url']})")
        if changed_cookies:
            print(f"  [쿠키 변화]")
            for k, v in changed_cookies.items():
                print(f"    [+] {k}: {v['before'] or '(없음)'} → {v['after']}")
        if changed_ls:
            print(f"  [localStorage 변화]")
            for k, v in changed_ls.items():
                print(f"    [+] {k} = {str(v)[:200]}")
        if changed_ss:
            print(f"  [sessionStorage 변화]")
            for k, v in changed_ss.items():
                print(f"    [+] {k} = {str(v)[:200]}")
        if new_lines:
            print(f"  [DOM 변화]")
            for line in new_lines[:20]:
                print(f"    {line}")

        result = ButtonResultItem(
            page_url=page_url,
            button=label,
            api_calls=api_calls or [],
            set_cookies=set_cookies or [],
            response_headers=resp_headers or [],
            cookie_changes=changed_cookies or {},
            localstorage_changes=changed_ls or {},
            sessionstorage_changes=changed_ss or {},
            dom_changes=new_lines[:20] if new_lines else [],
        )
        yield result

        already_clicked = response.meta.get('btn_already_clicked', frozenset())
        if new_lines and depth < 1:
            print(f"  [재탐색] DOM 변화로 새 버튼 탐색 시작")
            yield from self._schedule_button_clicks(page_url, depth=depth + 1,
                                                    already_clicked=already_clicked)

    # ── Playwright SPA 렌더링 ─────────────────────────────────────────────────

    @staticmethod
    def _make_api_interceptor(api_calls: list):
        import json as _json

        def handle(request):
            if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
                return
            url_lower = request.url.lower()
            if any(url_lower.endswith(ext) for ext in
                   ('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ico')):
                return
            post_data = request.post_data or ''
            content_type = request.headers.get('content-type', '')
            fields = []
            if 'application/json' in content_type:
                try:
                    payload = _json.loads(post_data)
                    if isinstance(payload, dict):
                        fields = list(payload.keys())
                except Exception:
                    pass
            elif 'application/x-www-form-urlencoded' in content_type:
                from urllib.parse import parse_qs as _pqs
                fields = list(_pqs(post_data).keys())
            if fields:
                api_calls.append({
                    'url': request.url,
                    'method': request.method,
                    'content_type': content_type,
                    'fields': fields,
                })

        return handle

    def parse_playwright_rendered(self, response):
        mode = response.meta.get('playwright_render_mode')
        if mode != 'spa_supplement':
            return

        api_calls = response.meta.get('captured_api_calls', [])
        spa_name  = response.meta.get('spa_name', 'SPA')
        item      = response.meta.get('partial_item')
        forms     = response.meta.get('existing_forms', [])

        print(f"\n# [Playwright SPA 렌더링] {response.url} ({spa_name})")
        print(f"    [+] DOM {len(response.text)} bytes, API calls {len(api_calls)}개 캡처")

        if api_calls:
            rendered_forms = self._api_calls_to_forms(api_calls)
        else:
            rendered_forms = self._extract_forms_from_rendered(response.text, response.url)

        existing_actions = {f['action'] for f in forms}
        added = 0
        for rf in rendered_forms:
            if rf['action'] not in existing_actions:
                forms.append(rf)
                existing_actions.add(rf['action'])
                added += 1

        if added:
            print(f"    [+] 렌더링 후 신규 폼 {added}개 추가")
        else:
            print(f"    [-] 추가 폼 없음 (정적 HTML과 동일)")

        # 렌더링된 HTML에서 링크 재수집 (SPA는 정적 응답보다 링크가 더 많을 수 있음, URL 중복 제거)
        start_host = urlparse(self.start_urls[0]).hostname
        seen_urls = set()
        rendered_links = []
        for a in response.css('a[href]'):
            href = response.urljoin(a.attrib['href'])
            if href in seen_urls:
                continue
            seen_urls.add(href)
            text = (a.css('::text').get() or '').strip()
            parsed_href = urlparse(href)
            rendered_links.append({
                'url':      href,
                'text':     text,
                'internal': parsed_href.hostname == start_host,
            })
        if rendered_links:
            item['links'] = rendered_links
            self._print_links(rendered_links)
            for link in rendered_links:
                if not link['internal'] or link['url'] in self._processed_urls:
                    continue
                ext = link['url'].rsplit('.', 1)[-1].split('?')[0].lower()
                if ext in _SKIP_EXTENSIONS:
                    continue
                yield scrapy.Request(link['url'], callback=self.parse_item,
                                     errback=self.ignore_error)

        item['forms'] = forms
        yield item

        form_params  = {inp['name'] for f in forms for inp in f['inputs'] if inp.get('name')}
        known_params = set(item['params'].keys()) | form_params
        yield from self._fuzz_get_params(response, known_params, item)
        for form in forms:
            if form['method'] == 'POST':
                yield from self._fuzz_post_params(form, item)
        yield from self._schedule_button_clicks(response.url)

    def _api_calls_to_forms(self, api_calls):
        forms = []
        seen_urls = set()
        for call in api_calls:
            action = call['url']
            if action in seen_urls:
                continue
            seen_urls.add(action)
            inputs = [{'name': f, 'type': 'text'} for f in call['fields']]
            forms.append({
                'action':       action,
                'method':       call['method'],
                'enctype':      call.get('content_type', 'application/json'),
                'inputs':       inputs,
            })
        return forms

    def _extract_forms_from_rendered(self, html, base_url):
        sel = scrapy.Selector(text=html)
        forms = []

        def _get_field_name(el):
            return el.attrib.get('name') or el.attrib.get('formcontrolname')

        def _extract_inputs(container):
            inputs = []
            for inp in container.css('input'):
                field_name = _get_field_name(inp)
                if not field_name:
                    continue
                inp_type = inp.attrib.get('type', 'text').lower()
                if inp_type in ('submit', 'button', 'image', 'reset', 'hidden', 'checkbox'):
                    continue
                inputs.append({'name': field_name, 'type': inp_type})
            for sel_el in container.css('select'):
                field_name = _get_field_name(sel_el)
                if not field_name:
                    continue
                inputs.append({
                    'name': field_name, 'type': 'select',
                    'options': sel_el.css('option::attr(value)').getall(),
                })
            for ta in container.css('textarea'):
                field_name = _get_field_name(ta)
                if not field_name:
                    continue
                inputs.append({'name': field_name, 'type': 'textarea'})
            return inputs

        for form in sel.css('form'):
            inputs = _extract_inputs(form)
            if not inputs:
                continue
            forms.append({
                'action':  urljoin(base_url, form.attrib.get('action', '')),
                'method':  form.attrib.get('method', 'get').upper(),
                'enctype': form.attrib.get('enctype', 'application/x-www-form-urlencoded').lower(),
                'inputs':  inputs,
            })

        if not forms:
            for container in sel.css('div, section'):
                has_submit = container.css(
                    'button[type="submit"], input[type="submit"], '
                    'button[id*="Button"], button[aria-label*="Login"], button[aria-label*="Submit"]'
                )
                if not has_submit:
                    continue
                inputs = _extract_inputs(container)
                if not inputs:
                    continue
                existing_names = {i['name'] for f in forms for i in f['inputs']}
                unique_inputs  = [i for i in inputs if i['name'] not in existing_names]
                if not unique_inputs:
                    continue
                forms.append({
                    'action':  base_url,
                    'method':  'POST',
                    'enctype': 'application/x-www-form-urlencoded',
                    'inputs':  unique_inputs,
                })
                break

        return forms

    # ── 퍼징 ──────────────────────────────────────────────────────────────────
    #
    # GET 쿼리스트링 퍼징(_fuzz_get_params)과 POST 폼 퍼징(_fuzz_post_params)은
    # "후보를 블록으로 나눠 diff 있는지 보고, 있으면 절반씩/이분탐색으로 좁혀간다"는
    # 알고리즘 자체(_start_block_fuzzing ~ _bs_check_solo)를 그대로 공유한다.
    # 전송 방식(GET 쿼리스트링 vs POST 폼 바디)과 변화 판정 방식만 다르므로, 그
    # 차이를 `state` 딕셔너리(ctx + baseline_text) 하나로 캡슐화해서 콜백 체인
    # 전체에 그대로 실어 나른다. ctx = {method, url, known_fields, probe_value}.

    @staticmethod
    def _load_wordlist(path):
        try:
            with open(path, encoding='utf-8') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            return []

    def _build_fuzz_request(self, state, params, callback, cb_kwargs, value=None):
        """state['ctx']에 따라 GET 쿼리스트링/POST 폼 바디로 요청을 만든다.

        known_fields(더미값)는 매 요청 같이 보내고, params(이번에 테스트하는 후보)에만
        값(기본은 ctx['probe_value'], value로 오버라이드 가능 — 발견된 파라미터의 우회값
        재검증용)을 채운다 — 신호가 known 필드 때문인지 후보 때문인지 안 섞이게.
        """
        ctx = state['ctx']
        probe_value = ctx['probe_value'] if value is None else value
        data = dict(ctx['known_fields'])
        data.update({p: probe_value for p in params})
        cb_kwargs = dict(cb_kwargs, state=state)
        if ctx['method'] == 'GET':
            url = f"{ctx['url']}?{'&'.join(f'{k}={v}' for k, v in data.items())}" if data else ctx['url']
            return scrapy.Request(
                url, callback=callback, errback=self.ignore_error,
                cb_kwargs=cb_kwargs, dont_filter=True, meta={'is_fuzz': True}, priority=-1,
            )
        return scrapy.FormRequest(
            ctx['url'], method='POST', formdata=data,
            callback=callback, errback=self.ignore_error,
            cb_kwargs=cb_kwargs, dont_filter=True, meta={'is_fuzz': True}, priority=-1,
        )

    def _is_changed(self, response, state):
        if response.status in (403, 429, 503):
            return False
        probe_value = state['ctx']['probe_value']
        return diff_score(state['baseline_text'], visible_text(response.text)) >= DIFF_SCORE_THRESHOLD \
            or probe_value in response.text

    # ── GET 쿼리스트링 퍼징 ──────────────────────────────────────────────────

    def _fuzz_get_params(self, response, known_params=None, item=None):
        base_url = response.url.split('?')[0]
        if base_url in self._fuzzed_urls:
            return
        self._fuzzed_urls.add(base_url)
        if not self._param_wordlist:
            return
        candidates = [p for p in self._param_wordlist if p not in (known_params or set())]
        if not candidates:
            return
        ctx = {'method': 'GET', 'url': base_url, 'known_fields': {}, 'probe_value': FUZZ_MARKER}
        state = {'ctx': ctx, 'baseline_text': visible_text(response.text)}
        yield from self._fuzz_start(state, candidates, item)

    # ── POST 폼 퍼징 ─────────────────────────────────────────────────────────

    def _fuzz_post_params(self, form, item):
        """폼마다 한 번, 진단(공격적 값 → 우회 재시도 → 숫자/문자열 dual-pass 폴백) 후
        확정된 probe_value로 실제 이분탐색 퍼징을 시작한다. 자세한 설계 배경(왜 3단계인지,
        known 필드에 왜 더미값만 쓰는지)은 대화 중 합의된 그대로다."""
        action, enctype = form['action'], form['enctype']
        if action in self._fuzzed_post_forms:
            return
        self._fuzzed_post_forms.add(action)
        if not self._param_wordlist:
            return

        known_fields = {
            inp['name']: (inp.get('value') or 'test')
            for inp in form['inputs']
            if inp.get('name') and inp.get('type') not in ('submit', 'button', 'image', 'reset')
        }
        candidates = [p for p in self._param_wordlist if p not in known_fields]
        if not candidates:
            return

        print(f"\n# [POST 폼 퍼징 진단] {action} — known_fields={list(known_fields.keys())}, "
              f"후보 {len(candidates)}개, 시작값=\"{POST_PROBE_AGGRESSIVE}\"")
        yield scrapy.FormRequest(
            action, method='POST', formdata={**known_fields, candidates[0]: POST_PROBE_AGGRESSIVE},
            callback=self._post_diagnose_step,
            errback=self.ignore_error,
            cb_kwargs=dict(candidates=candidates, known_fields=known_fields, action=action,
                           enctype=enctype, item=item, evade_index=None, probe_value=POST_PROBE_AGGRESSIVE),
            dont_filter=True, meta={'is_fuzz': True}, priority=-1,
        )

    def _post_diagnose_step(self, response, candidates, known_fields, action, enctype, item, evade_index, probe_value):
        """공격적 값(POST_PROBE_AGGRESSIVE)이 앱 자체 필터에 막히는지 진단한다.

        안 막히면 그 값 그대로 진행. 막히면 EVASION_TRANSFORMS를 하나씩 시도(적용할 게
        없는 변형은 요청 없이 건너뜀). 그것도 다 실패하면 특수문자 없이 "타입 불일치"만으로
        에러를 유발하는 숫자(9)/문자열(abc) 두 값으로 나눠 각각 독립적으로 퍼징한다 —
        이 진단은 폼 하나당 딱 한 번만 하고, 결과(모드)를 이후 전체 퍼징에 재사용한다.
        """
        tried_label = f'공격적 값 "{POST_PROBE_AGGRESSIVE}"' if evade_index is None else f'우회({EVASION_TRANSFORMS[evade_index][0]}) "{probe_value}"'
        blocked, waf_name, waf_evidence = classify_waf_block(response.status, response.text)
        print(f"    [진단] {tried_label} 전송 → status={response.status} blocked={blocked}"
              + (f" waf={waf_name} evidence={waf_evidence}" if blocked else ""))
        if not blocked:
            print(f"    [진단] 통과 — 이 값으로 이분탐색 진행: \"{probe_value}\"")
            yield from self._post_fuzz_start(action, enctype, known_fields, candidates, probe_value, item)
            return

        next_index = 0 if evade_index is None else evade_index + 1
        while next_index < len(EVASION_TRANSFORMS):
            name, transform = EVASION_TRANSFORMS[next_index]
            variant = transform(POST_PROBE_AGGRESSIVE)
            if variant != POST_PROBE_AGGRESSIVE:
                print(f"    [진단] 우회 시도: {name} → \"{variant}\"")
                yield scrapy.FormRequest(
                    action, method='POST', formdata={**known_fields, candidates[0]: variant},
                    callback=self._post_diagnose_step,
                    errback=self.ignore_error,
                    cb_kwargs=dict(candidates=candidates, known_fields=known_fields, action=action,
                                   enctype=enctype, item=item, evade_index=next_index, probe_value=variant),
                    dont_filter=True, meta={'is_fuzz': True}, priority=-1,
                )
                return
            print(f"    [진단] 우회({name}) 적용 대상 아님 — 스킵")
            next_index += 1

        print(f"    [진단] 필터 차단 + 우회 {len(EVASION_TRANSFORMS)}종 전부 실패 — 숫자/문자열 dual-pass 모드로 전환")
        yield from self._post_fuzz_start(action, enctype, known_fields, candidates, POST_PROBE_NUMERIC, item)
        yield from self._post_fuzz_start(action, enctype, known_fields, candidates, POST_PROBE_ALPHA, item)

    def _post_fuzz_start(self, action, enctype, known_fields, candidates, probe_value, item):
        """진단으로 확정된 probe_value로 known 필드만 채운 baseline을 한 번 받고, 실제
        이분탐색 퍼징(GET과 공유하는 _check_initial_batch~)을 시작한다."""
        ctx = {'method': 'POST', 'url': action, 'enctype': enctype,
               'known_fields': known_fields, 'probe_value': probe_value}
        yield scrapy.FormRequest(
            action, method='POST', formdata=known_fields,
            callback=self._post_fuzz_baseline,
            errback=self.ignore_error,
            cb_kwargs=dict(ctx=ctx, candidates=candidates, item=item),
            dont_filter=True, meta={'is_fuzz': True}, priority=-1,
        )

    def _post_fuzz_baseline(self, response, ctx, candidates, item):
        state = {'ctx': ctx, 'baseline_text': visible_text(response.text)}
        yield from self._fuzz_start(state, candidates, item)

    # ── 이분탐색 알고리즘 (GET/POST 공유) ────────────────────────────────────

    @staticmethod
    def _make_canary() -> str:
        """절대 실제 파라미터일 리 없는 이름 — 이분탐색 신뢰도 사전 점검용."""
        return f"zzfbzcanary{uuid.uuid4().hex[:6]}"

    def _fuzz_start(self, state, candidates, item):
        """실제 이분탐색(비용이 큼: 최소 log(n) 요청) 전에, 존재할 리 없는 카나리 파라미터
        하나로 먼저 찔러본다. 카나리조차 baseline과 달라지면 이 폼/페이지는 '모르는 필드엔
        무조건 다르게 반응'하는 걸로 봐야 해서, 그 뒤로 어떤 후보를 넣어도 diff가 날 텐데
        그게 그 후보가 실제로 쓰여서인지 그냥 안 쓰는 필드라서인지 구분할 방법이 없다 —
        그럴 땐 비싼 이분탐색을 아예 안 돌리고 여기서 요청 1개로 저렴하게 포기한다."""
        canary = self._make_canary()
        yield self._build_fuzz_request(
            state, [canary], self._check_canary, cb_kwargs=dict(candidates=candidates, item=item, canary=canary),
        )

    def _check_canary(self, response, candidates, item, state, canary):
        url = state['ctx']['url']
        method = state['ctx']['method']
        if self._is_changed(response, state):
            print(f"\n# [카나리 실패][{method}] {url} — 존재하지 않는 필드({canary})에도 반응이 달라짐. "
                  f"이 폼/페이지는 모르는 필드에 균일하게 반응하는 걸로 보여 퍼징 신뢰 불가 — 스킵 (수동 확인 권장)")
            return
        print(f"\n# [퍼징 시작][{method}] {url} — 카나리 통과, {len(candidates)}개 파라미터")
        yield self._build_fuzz_request(
            state, candidates, self._check_initial_batch, cb_kwargs=dict(candidates=candidates, item=item),
        )

    def _check_initial_batch(self, response, candidates, item, state):
        url = state['ctx']['url']
        method = state['ctx']['method']
        if response.status in (403, 429, 503):
            print(f"\n# [초기 배치 차단][{method}] {url} — WAF/길이 제한 의심, 블록 알고리즘 진행")
        elif not self._is_changed(response, state):
            score = diff_score(state['baseline_text'], visible_text(response.text))
            blocked, waf_name, waf_evidence = classify_waf_block(response.status, response.text)
            print(f"\n# [초기 배치 무변화][{method}] {url} — status={response.status} "
                  f"diff_score={score}(임계값 {DIFF_SCORE_THRESHOLD}) blocked={blocked}"
                  + (f" waf={waf_name} evidence={waf_evidence}" if blocked else "")
                  + f" — 후보 {len(candidates)}개 전부에서 신호 없음, 퍼징 종료")
            return
        else:
            print(f"\n# [초기 배치 변화][{method}] {url} — 블록 알고리즘 진행")
        yield from self._start_block_fuzzing(candidates, item, state)

    def _start_block_fuzzing(self, candidates, item, state):
        blocks = [candidates[i:i + BLOCK_SIZE] for i in range(0, len(candidates), BLOCK_SIZE)]
        print(f"    [+] → {len(blocks)}개 블록으로 분할")
        if len(blocks) == 1:
            yield self._build_fuzz_request(
                state, blocks[0], self._check_single_block, cb_kwargs=dict(block=blocks[0], item=item),
            )
            return
        # 페어 조합 전에 블록을 각각 단독으로 먼저 찔러본다 — _check_single_block/
        # _single_split_step 경로가 "혼자서 무신호"를 확인한 뒤에야 anchor로 쓰는 것과 같은
        # 원칙이다. 이걸 안 하면, 진짜 파라미터를 담은 블록이 어느 페어에서 우연히 anchor(b1)
        # 역할로 쓰일 때 anchor 자신의 신호 때문에 search(b2) 쪽 이분탐색이 어느 절반을 골라도
        # 항상 "변화 있음"만 보게 되어 b2 안의 무관한 임의 원소가 파라미터로 오탐되고, 정작
        # anchor 자신은 검증 없이 그냥 넘어가 버린다.
        block_state = {'pending': len(blocks), 'silent_blocks': []}
        for block in blocks:
            yield self._build_fuzz_request(
                state, block, self._check_block_solo,
                cb_kwargs=dict(block=block, item=item, block_state=block_state),
            )

    def _check_block_solo(self, response, block, item, state, block_state):
        if self._is_changed(response, state):
            # 이 블록은 혼자서도 신호를 낸다 — 이미 안전한(단독 무신호 확인 후 anchor 승격)
            # 단일 블록 경로로 그대로 넘긴다.
            yield from self._check_single_block(response, block, item, state)
        else:
            block_state['silent_blocks'].append(block)
        block_state['pending'] -= 1
        if block_state['pending'] == 0:
            yield from self._start_pairwise_phase(block_state['silent_blocks'], item, state)

    def _start_pairwise_phase(self, blocks, item, state):
        """단독으로는 무신호임이 이미 확인된 블록들끼리만 페어 조합을 시도한다 — 이 시점부턴
        어느 쪽을 anchor로 써도 '혼자서는 무신호'가 보장돼 있어 이후 이분탐색(_bs_search)의
        신호가 항상 search 쪽 부분집합 때문이라고 믿을 수 있다."""
        if len(blocks) < 2:
            return
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                b1, b2 = blocks[i], blocks[j]
                yield self._build_fuzz_request(
                    state, b1 + b2, self._check_block_pair, cb_kwargs=dict(b1=b1, b2=b2, item=item),
                )

    def _check_single_block(self, response, block, item, state):
        if not self._is_changed(response, state):
            return
        if len(block) == 1:
            yield from self._record_hidden_param(block[0], state, item, response)
            return
        mid = len(block) // 2
        left, right = block[:mid], block[mid:]
        print(f"\n# [단일 블록 변화] {state['ctx']['url']} — 절반 분할 ({len(left)}|{len(right)})")
        yield self._build_fuzz_request(
            state, left, self._single_split_step, cb_kwargs=dict(left=left, right=right, item=item),
        )

    def _single_split_step(self, response, left, right, item, state):
        if self._is_changed(response, state):
            if len(left) == 1:
                yield from self._record_hidden_param(left[0], state, item, response)
            else:
                mid = len(left) // 2
                sub_left, sub_right = left[:mid], left[mid:]
                yield self._build_fuzz_request(
                    state, sub_left, self._single_split_step,
                    cb_kwargs=dict(left=sub_left, right=sub_right, item=item),
                )
        else:
            print(f"\n# [분할 탐지] {state['ctx']['url']} — 앵커 이분 탐색")
            yield from self._bs_search(
                anchor=left, search=right, item=item, state=state, phase='find_p2', b1=left, p2=None,
            )

    def _check_block_pair(self, response, b1, b2, item, state):
        if not self._is_changed(response, state):
            return
        print(f"\n# [블록 조합 변화] {state['ctx']['url']} — 앵커 이분 탐색 (b1={len(b1)}, b2={len(b2)})")
        yield from self._bs_search(
            anchor=b1, search=b2, item=item, state=state, phase='find_p2', b1=b1, p2=None,
        )

    def _bs_search(self, anchor, search, item, state, phase, b1, p2):
        if not search:
            return
        if len(search) == 1:
            yield self._build_fuzz_request(
                state, anchor + search, self._bs_verify,
                cb_kwargs=dict(candidate=search[0], anchor=anchor, item=item, phase=phase, b1=b1, p2=p2),
            )
            return
        mid = len(search) // 2
        left, right = search[:mid], search[mid:]
        yield self._build_fuzz_request(
            state, anchor + left, self._bs_step,
            cb_kwargs=dict(anchor=anchor, left=left, right=right, item=item, phase=phase, b1=b1, p2=p2),
        )

    def _bs_step(self, response, anchor, left, right, item, state, phase, b1, p2):
        next_search = left if self._is_changed(response, state) else right
        yield from self._bs_search(anchor, next_search, item, state, phase, b1, p2)

    def _bs_verify(self, response, candidate, anchor, item, state, phase, b1, p2):  # noqa: anchor/p2 are cb_kwargs required by Scrapy
        if not self._is_changed(response, state):
            return
        if phase == 'find_p2':
            yield self._build_fuzz_request(
                state, [candidate], self._bs_check_solo, cb_kwargs=dict(p2=candidate, item=item, b1=b1),
            )
        else:
            yield from self._record_hidden_param(candidate, state, item, response)

    def _bs_check_solo(self, response, p2, item, state, b1):
        yield from self._record_hidden_param(p2, state, item, response)
        if not self._is_changed(response, state):
            print(f"\n# [복합 파라미터] {p2} + b1 이분 탐색 @ {state['ctx']['url']}")
            yield from self._bs_search(
                anchor=[p2], search=b1, item=item, state=state, phase='find_p1', b1=b1, p2=p2,
            )

    def _record_hidden_param(self, param, state, item, response):
        """이분탐색이 '변화'를 확정한 시점의 응답을 넘겨받아, 그 신호가 WAF/앱 필터
        차단(예: baby-sqlite의 "No Hack!")으로 인한 건지 확인한다. 차단이라면 발견 자체는
        맞지만 지금 쓰고 있는 probe_value는 필터에 걸린다는 뜻이라, 그 파라미터 하나에
        대해서만 EVASION_TRANSFORMS를 재시도해서 실제로 통과하는 값을 찾아본다."""
        ctx = state['ctx']
        blocked, waf_name, waf_evidence = classify_waf_block(response.status, response.text)
        if not blocked:
            print(f"\n# [숨겨진 파라미터 발견] {param} @ {ctx['url']} ({ctx['method']})")
            yield from self._finalize_hidden_param(param, state, item, ctx['probe_value'], None)
            return
        print(f"\n# [숨겨진 파라미터 발견] {param} @ {ctx['url']} ({ctx['method']}) — "
              f"단 이 신호는 필터 차단(waf={waf_name}, evidence={waf_evidence}) 때문. "
              f"원래 값 \"{ctx['probe_value']}\"이 걸려서 우회 값 탐색 시작")
        yield from self._evade_found_param(param, state, item, evade_index=0)

    def _evade_found_param(self, param, state, item, evade_index):
        ctx = state['ctx']
        if evade_index >= len(EVASION_TRANSFORMS):
            print(f"    [우회] {param} — 우회 {len(EVASION_TRANSFORMS)}종 전부 실패, "
                  f"차단된 값 그대로 기록: \"{ctx['probe_value']}\"")
            yield from self._finalize_hidden_param(param, state, item, ctx['probe_value'], 'blocked')
            return
        _, transform = EVASION_TRANSFORMS[evade_index]
        variant = transform(ctx['probe_value'])
        if variant == ctx['probe_value']:
            yield from self._evade_found_param(param, state, item, evade_index + 1)
            return
        yield self._build_fuzz_request(
            state, [param], self._check_evade_found_param,
            cb_kwargs=dict(param=param, item=item, evade_index=evade_index, variant=variant),
            value=variant,
        )

    def _check_evade_found_param(self, response, param, item, evade_index, variant, state):
        blocked, _, _ = classify_waf_block(response.status, response.text)
        if not blocked:
            name = EVASION_TRANSFORMS[evade_index][0]
            print(f"    [우회] {param} — {name} 우회 성공 → \"{variant}\"")
            yield from self._finalize_hidden_param(param, state, item, variant, name)
            return
        yield from self._evade_found_param(param, state, item, evade_index + 1)

    def _finalize_hidden_param(self, param, state, item, confirmed_value, evasion_used):
        ctx = state['ctx']
        if item is None:
            return
        if ctx['method'] == 'GET':
            if param in item['hidden_params']:
                return
            item['hidden_params'].append(param)
        else:
            # 같은 폼을 dual-pass(숫자/문자열)로 두 번 돌 때 같은 파라미터가 양쪽에서 다
            # 잡힐 수 있어서, action+param 기준으로 중복 기록을 막는다.
            if any(e['param'] == param and e['action'] == ctx['url'] for e in item['hidden_post_params']):
                return
            item['hidden_post_params'].append({
                'param':            param,
                'action':           ctx['url'],
                'enctype':          ctx.get('enctype'),
                'known_fields':     ctx['known_fields'],
                'confirmed_value':  confirmed_value,
                'evasion_used':     evasion_used,
            })
        item['_fuzz_update'] = True
        yield item

    # ── 출력 ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _print_tech_stack(tech_stack: dict):
        print(f"\n# [기술 스택]")
        fields = [
            ('server',    '웹서버    '),
            ('language',  '언어      '),
            ('framework', '프레임워크'),
            ('cms',       'CMS       '),
            ('spa',       'SPA       '),
            ('session',   '세션쿠키  '),
        ]
        for key, label in fields:
            val = tech_stack.get(key)
            marker = '[+]' if val else '[-]'
            print(f"    {marker} {label}: {val or '없음'}")
        for jwt_info in tech_stack.get('jwt_cookies', []):
            print(f"    [+] JWT 쿠키      : {jwt_info['name']} → {jwt_info['payload']}")
