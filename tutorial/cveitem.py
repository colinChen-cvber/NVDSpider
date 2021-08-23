import scrapy

class cveitem(scrapy.Item):
    cve_id = scrapy.Field()
    version = scrapy.Field()