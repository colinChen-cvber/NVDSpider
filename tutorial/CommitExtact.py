import os
import csv


vendor = 'openssl'
production = 'openssl'
version = '1.1.0'
keywords = []

with open('./data/data/{v}_{p}_{ver}/{v}_{p}_{ver}.csv'.format(v = vendor, p = production, ver = version), 'r') as f:
    reader = csv.reader(f)
    for i,rows in enumerate(reader):
        if i >= 1:
            keywords.append(rows[0])
        # print(rows)
    f.close()
os.chdir("D:\Github\{}".format(production))

for keyword in keywords:
    os.system(
        'git log -p --grep="{k}" >D:/project/tutorial/tutorial/data/data/{v}_{p}_{ver}/{k}.txt'.format(k=keyword, v=vendor, p=production, ver=version)
    )
# for keyword,fr,u in keywords:
#     os.system(
#         'git log -p --grep="{k}" >D:/project/tutorial/tutorial/data/openssl_openssl/{k}.txt'.format(k=keyword)
#     )
#     with open('D:/project/tutorial/tutorial/data/openssl_openssl/{k}.txt'.format(k=keyword), 'r+') as f:
#         content = f.read()
#         f.seek(0, 0)
#         f.write('affected_version:\n'+fr + u + '\n'+content)
#     # print(keyword)
# for cve_id,version,commit in keywords:
#     commits = commit.split(',')
#     for i,c in enumerate(commits):
#         os.system(
#             'git show {c} >D:/project/tutorial/tutorial/data/ffmpeg_ffmpeg/{k}_{c}.txt'.format(c=c, k=cve_id,v=version,i=i)
#         )



