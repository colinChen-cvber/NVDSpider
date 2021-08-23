# -*- coding: utf-8 -*-
import scrapy
from tutorial.cveitem import cveitem
import re

class CvespiderSpider(scrapy.Spider):
    name = "cvespider"
    vendor = "openssl"
    product = "openssl"
    versions = ['1.0.1', '1.0.2', '1.1.0', '1.1.1']
    tags = ['', 'a',
            'b', 'c', 'd', 'e','f', 'g','h', 'i', 'j', 'k']
        # , 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x']
    allowed_domains = ["nvd.nist.gov/vuln/search"]
    start_urls = ['http://nvd.nist.gov/vuln/search/results?form_type=Advanced/']
    with open('./data/openssl/openssl_cve.txt', 'r') as f:
        openssl_cve = f.read().split()

    def start_requests(self):
        for tag in self.tags:
            url = 'http://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&' \
                  'cpe_vendor=cpe%3A%2F%3A{vendor}&cpe_product=cpe%3A%2F%3A{vendor}%3A{product}&cpe_version=cpe%3A%2F%3A{vendor}%3A{product}%3A{version}{tag}'\
                .format(vendor=self.vendor, product=self.product, version=self.versions[3],tag=tag)
            yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        item = cveitem()
        version = re.findall("1.1.1[a-z]*", response.url)
        openssl_cve = self.openssl_cve
        nexturl = response.xpath('//a[@data-testid="pagination-link-page->"]/@href').get()
        url = response.urljoin(nexturl)
        cve_list = response.xpath('//a[contains(@data-testid,"vuln-detail-link")]/text()').getall()
        for cve in cve_list:
            if cve in openssl_cve:
                item['cve_id'] = cve
                item['version'] = version
                yield item
        if nexturl:
            yield scrapy.Request(url, callback=self.parse, dont_filter=True)
