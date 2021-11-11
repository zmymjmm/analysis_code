import datetime
import pymysql
import uuid
import csv
from elasticsearch import Elasticsearch
import pandas as pd


# 将字符串中的空格替换为"_"
def replaceSpace(s):
    l = list(s)
    for i in range(len(l)):
        if l[i] == ' ':
            l[i] = '_'
    return ''.join(l)

# 从ELK提取数据
es = Elasticsearch(
    ['10.112.254.160'],  # 连接集群，以列表的形式存放节点的ip地址
    scheme="https",
    port=64298,
    use_ssl=True,
    verify_certs=False    # 忽略elasticsearch引发证书验证失败的SSL错误
)
print(es.info())
print(es.ping())

# base日期(2021-11-08)和其对应的索引后缀
base_index = 13
# 获取前一天时间yes_day
now_time = datetime.datetime.now()
yes_time = (now_time+datetime.timedelta(days=-1)).strftime("%Y.%m.%d")
print("前一天日期:", yes_time)
# 获取索引后缀index
# 计算前一天和base日期的天数差值
now_str = now_time.strftime('%Y-%m-%d')
now = datetime.datetime.strptime(now_str, "%Y-%m-%d")
base = datetime.datetime.strptime("2021-11-08", "%Y-%m-%d")
dis = (now - base).days - 1
index = str(base_index + dis).zfill(6)
print("索引后缀:", index)

# 控制时间间隔，为1个小时
utc = datetime.datetime.utcnow()
now_utc = utc.strftime("%Y-%m-%dT%H:%M:%S.Z")
yes_utc = (utc+datetime.timedelta(hours=-1)).strftime("%Y-%m-%dT%H:%M:%S.Z")

response = es.search(
    index="logstash-" + str(yes_time) + "-" + index,  # 索引名
    body={  # 请求体
        "query": {  # 关键字，把查询语句给 query
            "bool": {  # 关键字，表示使用 filter 查询，没有匹配度
                "must": [],  # 表示里面的条件必须匹配，多个匹配元素可以放在列表里
                "must_not": {  # 关键字，表示查询的结果里必须不匹配里面的元素
                    "match": {  # 关键字
                        "message": "M("  # message 字段名，这个字段的值一般是查询到的结果内容体。这里的意思是，返回的结果里不能包含特殊字符 'M('
                    }
                },
                'filter': {
                    'range': {
                        "@timestamp": {
                            "gte": str(yes_utc),
                            "lte": str(now_utc)
                        }
                    }
                }
            }
        },
        # 下面是对返回的结果继续排序
        "sort": [{"@timestamp": {"order": "desc"}}],
        "from": 0,  # 从匹配到的结果中的第几条数据开始返回，值是匹配到的数据的下标，从 0 开始
        "size": 10000  # 返回多少条数据,最多就是10000
    }
)

total = response['hits']['total']
print(total)

# 先将数据存储到字典
res_dict = {"id" : "value", "time" : "value1", "src_ip" : "value2", "src_port" : "value3", "dest_ip" : "value4", "dest_port" : "value5", "event_type" : "value6", "killline": "value7"}
num = 1
# 声明空列表
id = []
time = []
src_ip = []
src_port = []
dest_ip = []
dest_port = []
event_type = []
killline = []
for hit in response['hits']['hits']:
    # 加了一行限制条件，因为foxpot收集的日志不光有suricata，还有p0f；但是p0f没有event_type这个字段
    if(hit['_source']['type'] == "suricata"):
        src_severity = "null"
        src_event_type = "null"
        # 查看hit['_source']是否存在key：src_port和dest_port
        if "src_port" in hit['_source'].keys():
            src_str = hit['_source']['src_port']
        else:
            src_str ="null"
        if "dest_port" in hit['_source'].keys():
            dest_str = hit['_source']['dest_port']
        else:
            dest_str = "null"
        # 查看hit['_source']是否存在key：alert;不存在的话本条数据不作记录
        if "alert" in hit['_source'].keys():
            if "category" in hit['_source']['alert'].keys():
                src_event_type = replaceSpace(hit['_source']['alert']['category'])
            if "severity" in hit['_source']['alert'].keys():
                src_severity = hit['_source']['alert']['severity']
        else:
            continue
        id.append(num)
        # 截取日期前10位
        time.append(hit['_source']['@timestamp'][0:10])
        src_ip.append(hit['_source']['src_ip'])
        src_port.append(src_str)
        dest_ip.append(hit['_source']['dest_ip'])
        dest_port.append(dest_str)
        event_type.append(src_event_type)
        killline.append(src_severity)
        num = num + 1
# 将读取的数据存入字典
res_dict["id"] = id
res_dict["time"] = time
res_dict["src_ip"] = src_ip
res_dict["src_port"] = src_port
res_dict["dest_ip"] = dest_ip
res_dict["dest_port"] = dest_port
res_dict["event_type"] = event_type
res_dict["killline"] = killline
print(res_dict)
print(num)  # 读取的总条数

print("--------------------------------------")
# 用pandas读取字典
pd.set_option('display.max_rows', None)
df = pd.DataFrame(res_dict)
df = df[['id', 'time', 'event_type', 'src_ip', 'dest_ip', 'killline']]
print(df[['time', 'event_type', 'killline']])

exit(0)

lst = []
for index, row in df.iterrows():
    row_l = row.tolist()
    lst.append(row_l)
print(len(lst))

lst_group = []
num = 0
for i in lst:
    tmp = i
    # print(i)
    num += 1
    lst_sub = []
    lst_sub.append(i)
    for j in lst[num:]:
        # if i[3] == j[3] and i[4] == j[4]:
        if tmp[4] == j[4]:
            lst_sub.append(j)
            tmp = j
            lst.remove(j)
        elif tmp[4] == j[3]:
            lst_sub.append(j)
            tmp = j
            lst.remove(j)
        else:
            continue
    # print(lst_sub)
    # print("-----------------")
    lst_group.append(lst_sub)

lst = lst_group
f = open('./tempkillline.txt', 'r', encoding='UTF-8')
killline = dict()
try:
    while True:
        line = f.readline()
        if line:
            tmp = line.split(' level:')
            # print(tmp)
            killline[tmp[0]] = float(tmp[1][0])
        else:
            break
except UnicodeError:
    print('encoding can not match:The encoding is error')
print('GET killline')
f.close()

f_mat = open('./mat_new.txt', 'r', encoding='GBK')
matp = dict()
while True:
    line = f_mat.readline()
    if line:
        tmp = line.split('---------')
        matp[tmp[0]] = tmp[1]
    else:
        break
print('Read transfer matrix')
f_mat.close()

all_attck_link = []
count = 0
# 每个类簇进行关联
for i in lst:
    if len(i) >= 5:
        count = count+1
        attack_link_list = []
        attack_list = []
        for index in range(len(i))[0:-1]:
            PA = i[index][2]
            local_num = -1
            if PA not in attack_list:  # 当前攻击是否出现过
                attack_name_link = []
                insert = 0
                max_P = 0
                max_loc = 0
                for anl in attack_link_list:  # 当前簇中的一条攻击链
                    local_num = local_num + 1  # 该攻击链在整个链表中的位置
                    tempmax_P = 0
                    for loc in range(len(anl))[1:]:  # 攻击链中攻击的位置
                        arc = str(str(anl[loc]) + '->' + PA)
                        if arc in matp.keys():  # 如果与现有攻击链中的攻击存在因果
                            insert = 1
                            if float(matp[arc].split('\n')[0])>tempmax_P:
                                tempmax_P = float(matp[arc].split('\n')[0])
                                tmpmax_PA = PA
                                tmpmax_id = i[index][0]
                    if tempmax_P > max_P:
                        max_P = tempmax_P
                        max_PA = tmpmax_PA
                        max_id = tmpmax_id
                        max_loc = local_num
                if insert == 1:
                    attack_link_list[local_num] = attack_link_list[max_loc] + [max_id] + [max_PA]
                    attack_list = attack_list + [PA]
                elif insert != 1:  # 如果没有加进去则添加成新的链
                    attack_name_link = [i[index][0]] + [PA]
                    attack_list = attack_list + [PA]
                    attack_link_list.append(attack_name_link)
                    # print(attack_link_list)
            else:
                continue
        all_attck_link.append(attack_link_list)
print(all_attck_link)
print('Get all the attack process')


final_list = []
# 将关联的结果用杀伤链进行筛选 可以改变if len(i[index]) >= 6和len(final_attack) >= 6的值增加结果
for i in all_attck_link:
    for index in range(len(i)):
        no = 0
        max_lev = 0
        final_attack = []
        if len(i[index]) >= 4:
            PA = i[index][1]
            try:
                a_lev = killline[PA]
                if a_lev >= 1:
                    for lev_loc in range(len(i[index]))[0:]:
                        if lev_loc % 2 != 0:
                            if killline[i[index][lev_loc]] >= a_lev:
                                a_lev = killline[i[index][lev_loc]]
                                max_lev = a_lev
                                final_attack = final_attack + [i[index][lev_loc-1]]+[i[index][lev_loc]]
            except KeyError:
                print('Key Error:' + PA)
        if max_lev >= 1 and len(final_attack) >= 4:
            final_list.append(final_attack)
f_attck = open('./result/finallsit.txt', 'w')
for model in final_list:
    attackline = ''
    for i in range(len(model)):
        attackline += str(model[i])+','
    f_attck.write(attackline[0:-1]+'\n')
f_attck.close()

print("----------------------------")
print(final_list)
for one_atc in final_list:
    att_cou = str(uuid.uuid1()).replace('-', '')
    backlog_id = att_cou
    process = 0
    index = 0
    while index < len(one_atc) - 1:
        process_list = []
        event_list = []
        event_id = one_atc[index]
        process += 1
        Killline = int(killline[one_atc[index + 1]])
        process_list.append(att_cou)
        process_list.append(event_id)
        process_list.append(process)
        process_list.append(Killline)
        f = open('./result/process_list.csv', 'a', newline='')
        writer = csv.writer(f)
        writer.writerow(process_list)
        f.close()
        index += 2
    id = att_cou
    attack_name = one_atc[-1]
    if killline[attack_name] >= 4:
        at_level = 'high'
    elif killline[attack_name] == 3:
        at_level = 'mid'
    else:
        at_level = 'low'
    log_id = one_atc[-2]
    frame_index = df[df.id == log_id].index.tolist()
    data_time = df.loc[frame_index, 'time'].tolist()[0]
    sattack = df.loc[frame_index, 'src_ip'].tolist()[0]
    dattack = df.loc[frame_index, 'dest_ip'].tolist()[0]
    risk_level = str(killline[attack_name] * 10)
    event_list.append(id)
    event_list.append(data_time)
    event_list.append(attack_name)
    event_list.append(sattack)
    event_list.append(dattack)
    event_list.append(at_level)
    f = open('./result/event_list.csv', 'a', newline='')
    writer = csv.writer(f)
    writer.writerow(event_list)
    f.close()

# 连接数据库
conn = pymysql.connect(
    host = '172.16.39.128',
    user = 'root',
    password = '123456',
    db = 'alienvault_siem',
    charset= 'utf8'
)
cursor = conn.cursor()
print('Successful connect the database')

# sqlbl = "select max(id) from topic3_event"
# try:
#    # 执行SQL语句
#    cursor.execute(sqlbl)
#    # 获取所有记录列表
#    results = cursor.fetchall()
#    for row in results:
#       maxId = row[0]
#       print(maxId)
# except:
#    print("Error: unable to find maxId")
#
# # 往topic3_event表插入数据
# id = maxId + 1
# lst = df.values.tolist()
# for i in lst:
#     sqlbl = "INSERT INTO topic3_event(id,attack_time,time,logstr,src_ip,dst_ip) values(%s,'%s','%s','%s','%s','%s')" % (id + int(i[0]),
#     str(i[1]), str(i[1]), str(i[2]), str(i[3]), str(i[4]))
#     cursor.execute(sqlbl)
#     conn.commit()
#     print('Success insert a record!')
#
#
# df = pd.read_csv('./result/event_list.csv', encoding='UTF-8', names = ['id', 'datetime',' risk_level', 'src_ip', 'dst_ip', 'level'])
# print(df)
# lst = df.values.tolist()
# for i in lst:
#     sqlbl = "INSERT INTO topic3_backlog values('%s','%s','%s',%s,'%s','%s','%s')" % (str(i[0]),
#     str(i[1]), str(i[2]), 40, str(i[3]), str(i[4]), str(i[5]))
#     cursor.execute(sqlbl)
#     conn.commit()
#     print('Success insert a record!')
#
# id = maxId + 1
# df = pd.read_csv('./result/process_list.csv', encoding='UTF-8', names=['backlog_id', 'event_id', 'process', 'killline'])
# print(df)
# lst = df.values.tolist()
# for i in lst:
#     sqlbl = "INSERT INTO topic3_backlog_event values('%s',%s,%s,%s)" % (str(i[0]),
#     id + int(i[1]), int(i[2]), int(i[3]))
#     cursor.execute(sqlbl)
#     conn.commit()
#     print('Success insert a record!')
#
# cursor.close()
# conn.close()