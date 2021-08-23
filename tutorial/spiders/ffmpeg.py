# -*- coding: utf-8 -*-
import scrapy
import re
from tutorial.ffmpegitem import ffmpegitem

class FfmpegSpider(scrapy.Spider):
    name = "ffmpeg"
    allowed_domains = ["www.ffmpeg.org/security.html"]
    start_urls = ['http://www.ffmpeg.org/security.html']

    def parse(self, response):
        details = response.xpath('//pre/text()').getall()
        versions = response.xpath('//h3/text()').getall()
        # print(detail[0].split('\n'))
        for detail,version in zip(details[:21],versions[:21]):
            ds = detail.split('\n')
            # print(version)
            for d in ds:

                if d:
                    item = ffmpegitem()
                    # print(d.split(', ')[0], d.split(', ')[1])
                    item['version'] = version
                    item['cve_id'] = d.split(', ')[0]
                    item['commit'] = d.split(', ')[1].split(' / ')
                    yield item
                # print(d)
