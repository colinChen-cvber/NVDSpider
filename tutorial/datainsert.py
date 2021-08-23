import pymongo
import csv
import re
import os

DBNAME='cjl'
DBHOST='10.27.174.4'
DBPORT=27017
USERNAME='root'
PASSWORD='226'
servers = "mongodb://" + USERNAME+":" + PASSWORD+"@" + DBHOST + ":" + str(DBPORT)
conn = pymongo.MongoClient(servers)
db = conn[DBNAME]
# path = './data/data/openssl_openssl_1.1.1/openssl_openssl_1.1.1.csv'
# data_path = './data/data/openssl_openssl_1.1.1/'
path = './data/openssl_openssl/openssl_openssl.csv'
data_path = './data/openssl_openssl/'
# path = './data/data/openssl_openssl_1.1.0/openssl_openssl_1.1.0.csv'
# data_path = './data/data/openssl_openssl_1.1.0/'
missing_cve = []

collection_name = 'cve'
collection = db[collection_name]

with open('./data/data/openssl_openssl_1.1.1/CVE.txt', 'r+') as f:
    for line in f.readlines():
        line = line.strip('\n')
        missing_cve.append(line)
print(missing_cve)
def readcsv(path):
    keywords = []
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for i, rows in enumerate(reader):
            if i > 0:
                keywords.append([rows[0], rows[1], rows[5], rows[6], rows[2], rows[3], rows[4]])
            # print(rows)
        f.close()
    return keywords
items = readcsv(path)

files = os.listdir(data_path)
files = [i.split('.')[0] for i in files]
for item in items:
    accept_version = ['1.0.2', '1.0.1', '1.1.0', '1.1.1']
    ver_dict = {}
    ver_dict[accept_version[0]] = []
    ver_dict[accept_version[1]] = []
    ver_dict[accept_version[2]] = []
    ver_dict[accept_version[3]] = []
    affect_version = []
    p_version = []
    cpe_list = re.split('[\[\]\'\, ]', item[6])
    key_list = [chr(i) for i in range(97, 123)]
    up_ver = []
    for i in range(cpe_list.count('')):
        cpe_list.remove('')
    # print(cpe_list)
    for cpe in cpe_list:
        if accept_version[0] in cpe:
            ver_dict[accept_version[0]].append(cpe)
        elif accept_version[1] in cpe:
            ver_dict[accept_version[1]].append(cpe)
        elif accept_version[2] in cpe:
            ver_dict[accept_version[2]].append(cpe)
        elif accept_version[3] in cpe:
            ver_dict[accept_version[3]].append(cpe)
    # print(ver_dict[accept_version[0]])
    for ver in accept_version:
        if ver_dict[ver]:
            key = re.findall('[a-z]', ver_dict[ver][-1])

            affect_version.append('-'.join([ver_dict[ver][0], ver_dict[ver][-1]]))
            if ver_dict[ver][-1] == ver:
                p_version.append(ver + 'a')
            elif key and key[0] in key_list:
                key_index = key_list.index(key[0])
                if key_index == 25:
                    p_version.append(ver + key_list[key_index])
                else:
                    p_version.append(ver + key_list[key_index + 1])
    # print(p_version)
    # print(affect_version)

    # print(key_list)
    if item[0] in files:
        fr = re.findall('\d\.\d\.\d[a-z]*', item[4])
        ver = ["".join(re.findall('[^[a-z]', i)) for i in fr]
        up_flag = re.findall('Up to \(.*?\)', item[5])
        ups = re.findall('\d\.\d\.\d[a-z]*', item[5])
        for up, flag in zip(ups, up_flag):

            up_ver = "".join(re.findall('[^[a-z]', up))
            if up_ver in accept_version:
                # print(re.findall('[a-z]', up))
                for key in re.findall('[a-z]', up):
                    if key in key_list:
                        key_index = key_list.index(key)
                        if key_index == 25:
                            p_version.append(up_ver + key_list[key_index])
                        elif 'excluding' in flag and up_ver in ver and key_index > 0:
                            # print('包括')
                            p_version.append(up_ver + key_list[key_index])
                            index = ver.index("".join(re.findall('[^[a-z]', up)))
                            affect_version.append("-".join([fr[index], up_ver + key_list[key_index-1]]))
                        elif up_ver in ver:
                            p_version.append(up_ver + key_list[key_index + 1])
                            index = ver.index("".join(re.findall('[^[a-z]', up)))
                            affect_version.append("-".join([fr[index], up]))
                        else:
                            affect_version.append("-".join([up_ver, up]))
                            p_version.append(up_ver + key_list[key_index + 1])
                # if up_ver in ver:
                #     index = ver.index("".join(re.findall('[^[a-z]', up)))
                #     affect_version.append("-".join([fr[index], up]))
                # else:
                #     affect_version.append("-".join([up_ver, up]))
        # print(affect_version)
        # print(p_version)


        filename_list = []
        funcname_list = []



        with open(data_path+'{}.txt'.format(item[0]), 'r+') as f:
            content = f.read()
            split_list = content.split('diff')
            for para in split_list:
                file = re.findall('(?<= --git a/).*?\.c', para)

                if file and 'test' not in file[0]:
                    func = re.findall('(?<= @@ ).*(?=\()', para)
                    func = [i.split(' ')[-1] for i in func]
                    func = ["".join(re.findall('[^\*]', i)) for i in func]
                    if func:
                        funcname_list.append(func)
                        filename_list.append(file)
                    # print(func)

            # print(up_ver)
            dic = {}
            if funcname_list and filename_list and affect_version and p_version:
                dic['cveid'] = item[0]  # cve编号
                dic['filename-list'] = filename_list  # 漏洞存在的文件
                dic['funcname-list'] = [list(set(i)) for i in funcname_list]  # 影响的函数名
                dic['v-affect-version'] = affect_version  # 影响的版本
                dic['p-version'] = p_version  # 修复的版本
                dic['description'] = item[3]  # 漏洞信息描述
                dic['vul-type'] = item[2]  # 漏洞类别
                dic['vul-level'] = item[1]  # 漏洞危险等级

                collection.insert(dic)
            print(dic)




