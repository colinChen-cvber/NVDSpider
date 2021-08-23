import scrapy

class ffmpegitem(scrapy.Item):
    cve_id = scrapy.Field()
    version = scrapy.Field()
    commit = scrapy.Field()
