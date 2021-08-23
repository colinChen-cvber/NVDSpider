# -*- coding: utf-8 -*-
import scrapy


class BaiduSpider(scrapy.Spider):
    name = "baidu"
    allowed_domains = ["www.baidu.com"]
    start_urls = ['http://www.baidu.com/']

    def parse(self, response):
        title = response.xpath('//html/head/title/text()')
        print(title)
