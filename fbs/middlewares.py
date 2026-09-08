import logging
import random
from scrapy import signals
from scrapy.http import Request
from fake_useragent import UserAgent

logger = logging.getLogger(__name__)


class FuzzNoDelayMiddleware:
    """퍼징 요청을 전용 슬롯에 배정해 DOWNLOAD_DELAY 없이 병렬 처리."""

    FUZZ_SLOT = 'fuzz'

    @classmethod
    def from_crawler(cls, crawler):
        s = cls()
        s.crawler = crawler
        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)
        return s

    def spider_opened(self, spider):
        from scrapy.core.downloader import Slot
        downloader = self.crawler.engine.downloader
        concurrency = self.crawler.settings.getint('CONCURRENT_REQUESTS', 8)
        downloader.slots[self.FUZZ_SLOT] = Slot(concurrency, 0, False)

    def process_request(self, request, spider=None):
        # spider 인자는 is_fuzz 요청 경로에서 None으로 들어오는 경우가 있어(원인 불명,
        # scrapy_playwright/asyncio reactor 조합 이슈로 추정) 신뢰하지 않는다 — from_crawler에서
        # 미리 잡아둔 self.crawler를 대신 쓴다.
        if request.meta.get('is_fuzz'):
            request.meta['download_slot'] = self.FUZZ_SLOT
            slot = self.crawler.engine.downloader.slots.get(self.FUZZ_SLOT)
            if slot:
                slot.delay = random.uniform(0, 0.5)
        return None


class FuzzAwareDepthMiddleware:
    """scrapy.spidermiddlewares.depth.DepthMiddleware와 동일하지만, is_fuzz 요청은
    depth 추적/제한 대상에서 아예 제외한다.

    퍼징 체인(진단 → baseline → 카나리 → 이분탐색 분할...)은 링크를 더 깊이 크롤링하는 게
    아니라 이미 발견한 페이지 하나에 대한 진단 요청들이 여러 홉에 걸쳐 이어지는 것뿐인데,
    기본 DepthMiddleware는 이 홉들도 그냥 '크롤링 depth'로 세서 DEPTH_LIMIT을 넘기면
    DEBUG 레벨로 조용히(LOG_LEVEL=WARNING이라 안 보임) 요청을 버린다. 42개 후보 이분탐색만
    해도 log2(42)≈6단계가 더 필요해서 DEPTH_LIMIT을 늘리는 걸로는 근본 해결이 안 된다."""

    def __init__(self, maxdepth, stats, verbose_stats=False, prio=1):
        self.maxdepth = maxdepth
        self.stats = stats
        self.verbose_stats = verbose_stats
        self.prio = prio

    @classmethod
    def from_crawler(cls, crawler):
        settings = crawler.settings
        maxdepth = settings.getint('DEPTH_LIMIT')
        verbose = settings.getbool('DEPTH_STATS_VERBOSE')
        prio = settings.getint('DEPTH_PRIORITY')
        return cls(maxdepth, crawler.stats, verbose, prio)

    def process_spider_output(self, response, result, spider):
        def _filter(request):
            if not isinstance(request, Request):
                return True
            if request.meta.get('is_fuzz'):
                return True
            depth = response.meta.get('depth', 0) + 1
            request.meta['depth'] = depth
            if self.prio:
                request.priority -= depth * self.prio
            if self.maxdepth and depth > self.maxdepth:
                logger.debug(
                    "Ignoring link (depth > %(maxdepth)d): %(requrl)s ",
                    {'maxdepth': self.maxdepth, 'requrl': request.url},
                    extra={'spider': spider},
                )
                return False
            if self.verbose_stats:
                self.stats.inc_value(f'request_depth_count/{depth}', spider=spider)
            self.stats.max_value('request_depth_max', depth, spider=spider)
            return True
        return (r for r in result if _filter(r))


class RandomUserAgentMiddleware:
    def __init__(self):
        self.ua = UserAgent()

    def process_request(self, request, spider=None):
        request.headers['User-Agent'] = self.ua.random
