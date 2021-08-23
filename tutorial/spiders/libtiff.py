# -*- coding: utf-8 -*-
import scrapy
import re
from tutorial.libtiff_items import libtiffitem

class LibtiffSpider(scrapy.Spider):
    name = "libtiff"
    allowed_domains = ["libtiff.maptools.org"]
    start_urls = ['http://libtiff.maptools.org/']

    def start_requests(self):
        for i in range(0, 6):
            url = "http://libtiff.maptools.org/v3.9.{}.html#libtiff".format(i)
            yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        new = response.xpath('//font[1]/ul[1]/text()[3]').get()
        old = response.xpath('//font[1]/ul[1]/a[1]/text()').get()
        keys = response.xpath("//li[contains(text(),'CVE')or contains(text(),'OSS Fuzz')]/text()").getall()
        for key in keys:
            item = libtiffitem()
            item['new_version'] = new
            item['old_version'] = old
            item['vul_id'] = re.findall('CVE.[0-9]+.[0-9]+', key)
            item['filename'] = re.findall("^.*(?!http).*\.c", key)
            item['oss_fuzz'] = re.findall("id=[1-9]+", key)
            item['func_name'] = re.findall("[a-zA-Z]+\(\)", key)
            item['detail'] = key
            print(key)
            yield item
