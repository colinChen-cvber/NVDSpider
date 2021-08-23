# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

import scrapy


class DmozItem(scrapy.Item):
    CVE_id = scrapy.Field()
    description = scrapy.Field()
    CVSS = scrapy.Field()
    cwe = scrapy.Field()
    cpe = scrapy.Field()
    patch = scrapy.Field()
    From = scrapy.Field()
    Upto = scrapy.Field()

