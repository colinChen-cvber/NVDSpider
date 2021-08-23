import scrapy

class libtiffitem(scrapy.Item):
    old_version = scrapy.Field()
    new_version = scrapy.Field()
    filename = scrapy.Field()
    func_name = scrapy.Field()
    detail = scrapy.Field()
    vul_id = scrapy.Field()
    oss_fuzz = scrapy.Field()
