import scrapy


class PageItem(scrapy.Item):
    url              = scrapy.Field()
    status_code      = scrapy.Field()
    content_type     = scrapy.Field()
    depth            = scrapy.Field()
    method           = scrapy.Field()
    params           = scrapy.Field()
    response_headers = scrapy.Field()
    cookies          = scrapy.Field()
    tech_stack       = scrapy.Field()
    forms            = scrapy.Field()
    links            = scrapy.Field()
    hidden_params    = scrapy.Field()
    hidden_post_params = scrapy.Field()
    _fuzz_update     = scrapy.Field()
    security_headers = scrapy.Field()


class ButtonResultItem(scrapy.Item):
    page_url            = scrapy.Field()
    button              = scrapy.Field()
    api_calls           = scrapy.Field()
    set_cookies         = scrapy.Field()
    response_headers    = scrapy.Field()
    cookie_changes      = scrapy.Field()
    localstorage_changes  = scrapy.Field()
    sessionstorage_changes = scrapy.Field()
    dom_changes         = scrapy.Field()
