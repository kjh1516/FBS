# Scrapy settings for fbs project
#
# For simplicity, this file contains only settings considered important or
# commonly used. You can find more settings consulting the documentation:
#
#     https://docs.scrapy.org/en/latest/topics/settings.html
#     https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
#     https://docs.scrapy.org/en/latest/topics/spider-middleware.html

BOT_NAME = "fbs"

SPIDER_MODULES = ["fbs.spiders"]
NEWSPIDER_MODULE = "fbs.spiders"

ADDONS = {}

TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
DOWNLOAD_HANDLERS = {
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}
PLAYWRIGHT_BROWSER_TYPE = "chromium"
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True}
PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT = 15000


# Crawl responsibly by identifying yourself (and your website) on the user-agent
#USER_AGENT = "fbs (+http://www.yourdomain.com)"

# Obey robots.txt rules
ROBOTSTXT_OBEY = False

LOG_LEVEL = 'WARNING'

HTTPERROR_ALLOWED_CODES = [400, 401, 403, 404, 405, 406, 422, 429, 444, 500, 503]

RETRY_HTTP_CODES = [429, 500, 503]
RETRY_TIMES = 3

# Crawl depth limit (0 = unlimited)
DEPTH_LIMIT = 3

# Concurrency and throttling settings
#CONCURRENT_REQUESTS = 16
CONCURRENT_REQUESTS_PER_DOMAIN = 1
DOWNLOAD_DELAY = 1

# ── 퍼징 레인 튜닝 (fuzz 전용 슬롯 — 일반 크롤 정중함과 별개) ──────────────────────
# 동시성을 올리고 delay를 낮추면 큰 단어장도 빠르게 끝나지만 서버를 세게 때린다. 고정 간격은
# 봇 지문이라 delay는 [MIN, MAX] 범위에서 랜덤 지터를 준다(MIN=MAX로 두면 고정).
#   느리고 정중하게 : scrapy crawl scanner -s FUZZ_DELAY_MAX=2 -s FUZZ_CONCURRENCY=2
#   빠르게(랩 환경) : scrapy crawl scanner -s FUZZ_DELAY_MAX=0 -s FUZZ_CONCURRENCY=16
FUZZ_CONCURRENCY = 8
FUZZ_DELAY_MIN   = 0.0
FUZZ_DELAY_MAX   = 0.5

# Disable cookies (enabled by default)
#COOKIES_ENABLED = False

# Disable Telnet Console (enabled by default)
#TELNETCONSOLE_ENABLED = False

# Override the default request headers:
#DEFAULT_REQUEST_HEADERS = {
#    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#    "Accept-Language": "en",
#}

# Enable or disable spider middlewares
# See https://docs.scrapy.org/en/latest/topics/spider-middleware.html
SPIDER_MIDDLEWARES = {
    # 퍼징 체인(진단→baseline→카나리→이분탐색)은 DEPTH_LIMIT 대상이 아니라서 기본
    # DepthMiddleware를 끄고 is_fuzz 요청을 예외 처리하는 버전으로 교체한다.
    'scrapy.spidermiddlewares.depth.DepthMiddleware': None,
    'fbs.middlewares.FuzzAwareDepthMiddleware': 900,
}

# Enable or disable downloader middlewares
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
DOWNLOADER_MIDDLEWARES = {
    'fbs.middlewares.FuzzNoDelayMiddleware': 350,
    # 기본 UserAgentMiddleware가 spider.user_agent를 전 크롤 요청에 적용한다(스캔당 UA 하나로
    # 고정). 요청마다 UA를 바꾸던 RandomUserAgentMiddleware는 diff 탐지 신호를 흔들어 제거했다.
}

# Enable or disable extensions
# See https://docs.scrapy.org/en/latest/topics/extensions.html
#EXTENSIONS = {
#    "scrapy.extensions.telnet.TelnetConsole": None,
#}

# Configure item pipelines
# See https://docs.scrapy.org/en/latest/topics/item-pipeline.html
ITEM_PIPELINES = {
    "fbs.pipelines.SQLitePipeline": 300,
}
SQLITE_DB_PATH = "fbs_results.db"

# Enable and configure the AutoThrottle extension (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/autothrottle.html
#AUTOTHROTTLE_ENABLED = True
# The initial download delay
#AUTOTHROTTLE_START_DELAY = 5
# The maximum download delay to be set in case of high latencies
#AUTOTHROTTLE_MAX_DELAY = 60
# The average number of requests Scrapy should be sending in parallel to
# each remote server
#AUTOTHROTTLE_TARGET_CONCURRENCY = 1.0
# Enable showing throttling stats for every response received:
#AUTOTHROTTLE_DEBUG = False

# Enable and configure HTTP caching (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#httpcache-middleware-settings
#HTTPCACHE_ENABLED = True
#HTTPCACHE_EXPIRATION_SECS = 0
#HTTPCACHE_DIR = "httpcache"
#HTTPCACHE_IGNORE_HTTP_CODES = []
#HTTPCACHE_STORAGE = "scrapy.extensions.httpcache.FilesystemCacheStorage"

# Set settings whose default value is deprecated to a future-proof value
FEED_EXPORT_ENCODING = "utf-8"
