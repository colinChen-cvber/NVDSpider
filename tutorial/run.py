from scrapy import cmdline

# 发行商，软件，版本
vendor = "openssl"
product = "openssl"
version = "1.1.0"
cmdline.execute('scrapy crawl vulspider -o ./data/data/{ven}_{p}_{v}/{ven}_{p}_{v}.csv -t csv'.format(ven=vendor, p=product, v=version).split())
# cmdline.execute('scrapy crawl ffmpeg -o ./data/{ven}_{p}/{ven}_{p}.csv -t csv'.format(ven=vendor, p=product).split())
# cmdline.execute('scrapy crawl libtiff -o ./data/libtiff_3.9.csv -t csv'.split())
# cmdline.execute('scrapy crawl cvespider -o ./data/openssl/openssl_1.1.1.csv -t csv'.split())

