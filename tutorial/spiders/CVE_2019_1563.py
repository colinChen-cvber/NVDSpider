# -*- coding: utf-8 -*-
import scrapy
from lxml import html

class Cve20191563Spider(scrapy.Spider):
    name = "CVE-2019-1563"
    allowed_domains = ["nvd.nist.gov/vuln/detail/CVE-2019-1563"]
    start_urls = ['http://nvd.nist.gov/vuln/detail/CVE-2019-1563/']

    def parse(self, response):
        CVE_id = response.xpath('//span[@data-testid="page-header-vuln-id"]/text()').extract()
        CVSS = response.xpath('//*[@data-testid="vuln-cvss3-panel-score"]').extract()
        print(CVE_id)

