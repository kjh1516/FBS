import base64
import zlib
import json
import re


# ── Flask 세션 ───────────────────────────────────────────────────────────────

def is_flask_session(cookie_name: str, cookie_value: str) -> bool:
    parts = cookie_value.split('.')
    if len(parts) < 3:
        return False
    compressed = cookie_value.startswith('.')
    payload = parts[1] if compressed else parts[0]
    try:
        padding = '=' * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        if compressed:
            decoded = zlib.decompress(decoded)
        json.loads(decoded)
        return True
    except Exception:
        return False


# ── JWT ──────────────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


def is_jwt(value: str) -> bool:
    return bool(_JWT_RE.match(value.strip()))


def decode_jwt_payload(value: str) -> dict | None:
    try:
        parts = value.strip().split('.')
        padding = '=' * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except Exception:
        return None


def header_decode(value, errors='replace') -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', errors=errors)
    return value


# ── 기술 스택 탐지 규칙 ───────────────────────────────────────────────────────

_POWERED_BY_RULES = [
    ('php',     'language',  'PHP'),
    ('express', 'framework', 'Express'),
    ('nestjs',  'framework', 'NestJS'),
    ('fastify', 'framework', 'Fastify'),
    ('koa',     'framework', 'Koa'),
    ('sails',   'framework', 'Sails.js'),
    ('next.js', 'framework', 'Next.js'),
    ('nuxt',    'framework', 'Nuxt.js'),
    ('django',  'framework', 'Django'),
    ('flask',   'framework', 'Flask'),
    ('asp.net', 'framework', 'ASP.NET'),
    ('node',    'language',  'Node.js'),
    ('ruby',    'language',  'Ruby'),
    ('python',  'language',  'Python'),
    ('java',    'language',  'Java'),
]

_SERVER_RULES = [
    ('nginx',             'server', 'Nginx'),
    ('apache',            'server', 'Apache'),
    ('iis',               'server', 'IIS'),
    ('caddy',             'server', 'Caddy'),
    ('openresty',         'server', 'OpenResty'),
    ('gunicorn',          'server', 'gunicorn'),
    ('uvicorn',           'server', 'uvicorn'),
    ('hypercorn',         'server', 'Hypercorn'),
    ('kestrel',           'server', 'Kestrel'),
    ('tomcat',            'server', 'Tomcat'),
    ('jetty',             'server', 'Jetty'),
    ('wildfly',           'server', 'WildFly'),
    ('werkzeug',          'server', 'Werkzeug'),
    ('phusion passenger', 'server', 'Phusion Passenger'),
    ('passenger',         'server', 'Phusion Passenger'),
]

_SERVER_LANG_HINTS = {
    'gunicorn':  ('language',  'Python'),
    'uvicorn':   ('language',  'Python'),
    'hypercorn': ('language',  'Python'),
    'werkzeug':  ('framework', 'Flask'),
    'kestrel':   ('language',  '.NET'),
    'tomcat':    ('language',  'Java'),
    'jetty':     ('language',  'Java'),
    'wildfly':   ('language',  'Java'),
    'passenger': ('language',  'Ruby'),
}

_COOKIE_EXACT = {
    'PHPSESSID':         ('language',  'PHP'),
    'JSESSIONID':        ('language',  'Java'),
    'connect.sid':       ('framework', 'Express'),
    'ASP.NET_SessionId': ('framework', 'ASP.NET'),
    'laravel_session':   ('framework', 'Laravel'),
    'sessionid':         ('framework', 'Django'),
    'rack.session':      ('framework', 'Rails'),
    '_rails_session':    ('framework', 'Rails'),
    'ci_session':        ('framework', 'CodeIgniter'),
    'symfony':           ('framework', 'Symfony'),
    'CAKEPHP':           ('framework', 'CakePHP'),
    'CFID':              ('language',  'ColdFusion'),
    'CFTOKEN':           ('language',  'ColdFusion'),
}

_COOKIE_PREFIX = [
    ('wordpress_', ('cms', 'WordPress')),
    ('wp_',        ('cms', 'WordPress')),
    ('django_',    ('framework', 'Django')),
]

_BODY_SIGNATURES = [
    ('/wp-content/',          'cms',       'WordPress'),
    ('/wp-includes/',         'cms',       'WordPress'),
    ('wp-json',               'cms',       'WordPress'),
    ('data-drupal-',          'cms',       'Drupal'),
    ('drupal.settings',       'cms',       'Drupal'),
    ('/sites/default/files/', 'cms',       'Drupal'),
    ('/components/com_',      'cms',       'Joomla'),
    ('csrfmiddlewaretoken',   'framework', 'Django'),
    ('authenticity_token',    'framework', 'Rails'),
    ('whitelabel error page', 'framework', 'Spring Boot'),
    ('<app-root',             'spa',       'Angular'),
    ('ng-version',            'spa',       'Angular'),
    ('__NEXT_DATA__',         'spa',       'Next.js'),
    ('data-reactroot',        'spa',       'React'),
]

_BODY_SIGNATURES_ICASE = [
    ('__nuxt',    'spa', 'Nuxt.js'),
    ('_reactroot', 'spa', 'React'),
]

_CDN_SPA = [
    ('vue',      'Vue'),
    ('react',    'React'),
    ('angular',  'Angular'),
    ('svelte',   'Svelte'),
    ('ember',    'Ember'),
    ('backbone', 'Backbone'),
]


def detect_tech_stack(headers: dict, cookies: list, body: str, url: str = '',
                      script_srcs: list = None) -> dict:
    """응답 헤더/쿠키/바디/스크립트 src에서 기술 스택 탐지.

    Returns:
        {
            'server':      str | None,
            'language':    str | None,
            'framework':   str | None,
            'cms':         str | None,
            'spa':         str | None,
            'session':     str | None,
            'jwt_cookies': list,
        }
    """
    result = {
        'server':      None,
        'language':    None,
        'framework':   None,
        'cms':         None,
        'spa':         None,
        'session':     None,
        'jwt_cookies': [],
    }

    def _set(field, value):
        if result[field] is None:
            result[field] = value

    # 헤더 정규화
    flat = {}
    for k, v in headers.items():
        flat[k.lower()] = (v[0] if isinstance(v, list) else v).lower()

    # 1. X-Powered-By
    powered_by = flat.get('x-powered-by', '')
    if powered_by:
        for keyword, field, value in _POWERED_BY_RULES:
            if keyword in powered_by:
                _set(field, value)
                if value == 'Express':
                    _set('language', 'Node.js')
                break

    # 2. Server 헤더
    server_header = flat.get('server', '')
    if server_header:
        for keyword, field, label in _SERVER_RULES:
            if keyword in server_header:
                _set(field, label)
                hint = _SERVER_LANG_HINTS.get(keyword)
                if hint:
                    _set(hint[0], hint[1])
                break

    # 3. 프레임워크 전용 헤더
    if 'x-aspnet-version' in flat:
        _set('framework', 'ASP.NET')
        _set('language', '.NET')
    if 'x-drupal-cache' in flat or 'x-drupal-dynamic-cache' in flat:
        _set('cms', 'Drupal')
    if 'x-runtime' in flat:
        _set('framework', 'Rails')
        _set('language', 'Ruby')
    if 'x-pingback' in flat:
        _set('cms', 'WordPress')

    # 4. 쿠키
    for cookie in cookies:
        name  = cookie.get('name', '')
        value = cookie.get('value', '')

        if name in _COOKIE_EXACT:
            field, val = _COOKIE_EXACT[name]
            _set(field, val)
            if result['session'] is None:
                result['session'] = name
            lang_map = {
                'PHP': 'PHP', 'Java': 'Java', 'Express': 'Node.js',
                'ASP.NET': '.NET', 'Laravel': 'PHP', 'Django': 'Python',
                'Rails': 'Ruby', 'CodeIgniter': 'PHP', 'Symfony': 'PHP',
            }
            if val in lang_map:
                _set('language', lang_map[val])

        for prefix, (field, val) in _COOKIE_PREFIX:
            if name.lower().startswith(prefix):
                _set(field, val)
                if result['session'] is None:
                    result['session'] = name

        if is_flask_session(name, value):
            _set('framework', 'Flask')
            _set('language', 'Python')
            if result['session'] is None:
                result['session'] = name

        if value and is_jwt(value):
            payload = decode_jwt_payload(value)
            result['jwt_cookies'].append({'name': name, 'payload': payload})

    # 5. 바디 시그니처
    head = body[:5000]
    for sig, field, val in _BODY_SIGNATURES:
        if sig in head:
            _set(field, val)

    head_lower = head.lower()
    for sig, field, val in _BODY_SIGNATURES_ICASE:
        if sig in head_lower:
            _set(field, val)

    # 6. URL 패턴
    url_lower = url.lower()
    if url_lower.endswith('.php'):
        _set('language', 'PHP')
    elif url_lower.endswith(('.asp', '.aspx')):
        _set('language', '.NET')
        _set('framework', 'ASP.NET')
    elif url_lower.endswith('.jsp'):
        _set('language', 'Java')
    if '/wp-admin/' in url_lower or '/wp-content/' in url_lower:
        _set('cms', 'WordPress')

    # 6-1. 페이지 내 링크/폼 액션에서 확장자 탐지 (현재 URL이 클린 URL인 경우 보완)
    import re as _re
    if result['language'] is None:
        if _re.search(r'(?:href|action|src)=["\'][^"\']*\.php[\s"\'?#]', body, _re.I):
            _set('language', 'PHP')
        elif _re.search(r'(?:href|action|src)=["\'][^"\']*\.jsp[\s"\'?#]', body, _re.I):
            _set('language', 'Java')
        elif _re.search(r'(?:href|action|src)=["\'][^"\']*\.aspx?[\s"\'?#]', body, _re.I):
            _set('language', '.NET')

    # 7. CDN <script src> 기반 SPA 탐지 (폴백)
    if result['spa'] is None:
        for src in (script_srcs or []):
            src_lower = src.lower()
            for key, name in _CDN_SPA:
                if key in src_lower:
                    result['spa'] = name
                    break
            if result['spa']:
                break

    return result
