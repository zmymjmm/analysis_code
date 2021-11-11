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
def get_ass():
    # 从ELK提取数据
    es = Elasticsearch(
        ['10.112.254.160'],  # 连接集群，以列表的形式存放节点的ip地址
        scheme="https",
        port=64298,
        use_ssl=True,
        verify_certs=False  # 忽略elasticsearch引发证书验证失败的SSL错误
    )

    print(es.info())
    print(es.ping())

    response = es.search(
        index="logstash",  # 索引名
        body={  # 请求体
            "query": {  # 关键字，把查询语句给 query
                "bool": {  # 关键字，表示使用 filter 查询，没有匹配度
                    "must": [],  # 表示里面的条件必须匹配，多个匹配元素可以放在列表里
                    "must_not": {  # 关键字，表示查询的结果里必须不匹配里面的元素
                        "match": {  # 关键字
                            "message": "M("  # message 字段名，这个字段的值一般是查询到的结果内容体。这里的意思是，返回的结果里不能包含特殊字符 'M('
                        }
                    }
                }
            },

            # 下面是对返回的结果继续排序
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": 0,  # 从匹配到的结果中的第几条数据开始返回，值是匹配到的数据的下标，从 0 开始
            "size": 10000  # 返回多少条数据
        }
    )

    total = response['hits']['total']
    print(total)

    # 先将数据存储到字典
    res_dict = {"id": "value", "time": "value1", "src_ip": "value2", "src_port": "value3", "dest_ip": "value4",
                "dest_port": "value5", "event_type": "value6", "killline": "value7"}
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
        if (hit['_source']['type'] == "suricata"):
            src_severity = "null"
            src_event_type = "null"
            # 查看hit['_source']是否存在key：src_port和dest_port
            if "src_port" in hit['_source'].keys():
                src_str = hit['_source']['src_port']
            else:
                src_str = "null"
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
    df = df[['id', 'time', 'event_type', 'src_ip', 'dest_ip']]
    return df


def init_matrix(path):
    list_name = pd.Series()
    data1 = []

    data = get_ass()
    data = data.values
    for i in data:
        # print(i[2])
        # print(findtype(i[2]))
        # exit(0)
        try:
            Atype = i[2]
            # Atype = i[2]
            print(Atype)
            data1.append(Atype)
        except TypeError:
            continue
    data1 = pd.DataFrame(data1, columns=['attacktype'])
    list_name = list_name.append(data1.drop_duplicates(['attacktype'])['attacktype'], ignore_index=True)

    list_name = list_name.drop_duplicates()
    Matrix_tmp = pd.DataFrame(0, columns=list_name, index=list_name)
    return Matrix_tmp


def findtype(ls):
    try:
        tmp = ls.split('type=')[1]
        tmp = tmp.split('}')[0]
        return tmp.replace('\x01', '').replace('\x02', '').replace('\ufeff', '').strip()
    except:
        return ls.replace('\x01', '').replace('\x02', '').replace('\ufeff', '').strip()


if __name__ == '__main__':
    # --------------------Configuration--Start--------------------------
    path = './'
    pd.set_option('display.max_columns', None)  # df输出显示所有列
    # --------------------Configuration---End---------------------------
    Matrix_tmp = init_matrix(path)  # 初始化一个全为0的矩阵

    data = get_ass()
    for indexs in data.index[0:-1]:
        # print(indexs)
        rows_f = data.loc[indexs].values
        # print(rows_f[2])
        fT = rows_f[2]  # subject,30,告警类型,fT为当前处理告警
        print(fT)
        rows_n = data.loc[indexs + 1].values
        nT = rows_n[2]
        if fT == nT:
            continue    # 不计自身转移概率
        else:
            Matrix_tmp[nT][fT] = Matrix_tmp[nT][fT] + 1

    Matrix_P = Matrix_tmp.div((Matrix_tmp.apply(sum, axis=1)), axis=0).fillna(0)  # 得到了转移概率矩阵
    f1 = open('./tran.txt', 'w')
    f1.write(str(Matrix_P))
    f1.close()
    # print(Matrix_P)
    # ----------------
    f = open('./mat_new.txt', 'w')

    for lines in Matrix_P.index:  # lines是行名
        Max_P_Array = Matrix_P.loc[lines].values[0:-1]
        # print(Max_P_Array)
        # exit(0)
        col_list = Matrix_P.columns.values.tolist()
        print(col_list)
        count = 0
        for values in Max_P_Array:
            if values <= 0:
                count += 1
                continue
            else:
                columns = col_list[count]
                count += 1
                print(lines + '->' + columns + '---------' + str(values))
                strmat = str(lines + '->' + columns + '---------' + str(values))
                f.write(strmat + '\n')
    f.close()
