import datetime
import pymysql
from elasticsearch import Elasticsearch
import pandas as pd


# 将字符串中的空格替换为"_"
def replaceSpace(s):
    l = list(s)
    for i in range(len(l)):
        if l[i] == ' ':
            l[i] = '_'
    return ''.join(l)

def readAndInsert():
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
    # print(res_dict)
    print(num)  # 读取的总条数

    print("--------------------------------------")
    # 用pandas读取字典
    pd.set_option('display.max_rows', None)
    df = pd.DataFrame(res_dict)
    df = df[['id', 'time', 'event_type', 'src_ip', 'dest_ip', 'killline']]
    # print(df[['time', 'event_type', 'killline']])

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

    sqlbl = "select max(id) from topic3_event"
    try:
       # 执行SQL语句
       cursor.execute(sqlbl)
       # 获取所有记录列表
       results = cursor.fetchall()
       for row in results:
          maxId = row[0]
          print(maxId)
    except:
       print("Error: unable to find maxId")

    # 往topic3_event表插入数据
    # topic3_event表初始无数据时，maxId初始化为0
    if maxId is None:
        maxId = 0
    id = maxId + 1
    lst = df.values.tolist()
    for i in lst:
        sqlbl = "INSERT INTO topic3_event(id,attack_time,time,logstr,src_ip,dst_ip) values(%s,'%s','%s','%s','%s','%s')" % (id + int(i[0]),
        str(i[1]), str(i[1]), str(i[2]), str(i[3]), str(i[4]))
        cursor.execute(sqlbl)
        conn.commit()
        # print('Success insert a record!')

    cursor.close()
    conn.close()

