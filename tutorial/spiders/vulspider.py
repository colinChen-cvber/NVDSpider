# -*- coding: utf-8 -*-
import scrapy
from tutorial.items import DmozItem
from scrapy_splash import SplashRequest
import re

class VulspiderSpider(scrapy.Spider):
    name = "vulspider"
    # 发行商，软件，版本
    vendor = "openssl"
    product = "openssl"
    version = "1.1.0"
    allowed_domains = ["nvd.nist.gov/vuln/search"]
    start_urls = ['http://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&'
                  'cpe_vendor=cpe%3A%2F%3A{vendor}&cpe_product=cpe%3A%2F%3A{vendor}%3A{product}'
                  '&cpe_version=cpe%3A%2F%3A{vendor}%3A{product}%3A{version}'
                  .format(vendor=vendor,product=product,version=version)]

    # start_urls = ['https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=CVE-2021-23839&search_type=all']

    def parse(self, response):
        detail_href = response.xpath('//a[contains(@data-testid,"vuln-detail-link")]/@href').getall()
        nexturl = response.xpath('//a[@data-testid="pagination-link-page->"]/@href').get()
        print(nexturl)
        # print(detail_href,nexturl)
        url = response.urljoin(nexturl)

        if nexturl:
            yield scrapy.Request(url, callback=self.parse, dont_filter=True)

        for href in detail_href:
            detail_url = response.urljoin(href)
            yield SplashRequest(detail_url, callback=self.parse_detail, dont_filter=True, args={'wait': 5.0})

    def parse_detail(self, response):
        item = DmozItem()
        item['CVE_id'] = response.xpath('//span[@data-testid="page-header-vuln-id"]/text()').get()
        item['description'] = response.xpath('//*[@data-testid="vuln-description"]/text()').get()
        item['CVSS'] = response.xpath("//a[@id='Cvss3NistCalculatorAnchor']/text()").get()
        item['From'] = response.xpath('//b[contains(@data-testid,"vuln-software-cpe")]/../b[contains(text(),"{}")]/../../td[contains(@data-testid,"start-range")]/b/text()'.format(self.product)).getall()
        item['Upto'] = response.xpath('//b[contains(@data-testid,"vuln-software-cpe")]/../b[contains(text(),"{}")]/../../td[contains(@data-testid,"end-range")]/b/text()'.format(self.product)).getall()
        # f = response.xpath('//td[contains(@data-testid,"vuln-software-cpe")]/b/text()').get()
        # item['From'] = response.xpath('//td[contains(@data-testid,"vuln-software-cpe")]/b/text()').getall()[1]
        cpe = response.xpath('//b[contains(@data-testid,"vuln-software-cpe")]/../b[contains(text(),"{}")]/text()'.format(self.product)).getall()
        item['cpe'] = [re.findall('\d\.\d\.\d[a-z]*', i) for i in cpe]
        item['cwe'] = response.xpath('//*[contains(@data-testid,"vuln-CWEs-link")]/a/text()').get()
        item['patch'] = response.xpath('//td[contains(@data-testid,"vuln-hyperlinks-resType")]/span/span[text()="Patch"]/../../../td[contains(@data-testid,"vuln-hyperlinks-link")]/a/@href').getall()
        # print(f)
        yield item
        # print(item['CVE_id'], item['description'], item['CVSS'],item['cwe'])


