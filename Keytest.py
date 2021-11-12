import pandas as pd
from dbConnect import *
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 从topic3_event表提取数据
def get_ass():
    # 重复连接数据库，直到连接成功才进行下一步操作
    while 1 == 1:
        try:
            conn = connect(logger)
            logger.info('Successful connect the database')
            break
        except:
            logger.info('reconnect the database')

    begin_time = "2021-11-11"
    end_time = "2021-11-11"
    sqlbl = "select id,time,logstr,src_ip,dst_ip from topic3_event where time between '%s' and '%s'" % (begin_time, end_time)
    df = pd.read_sql_query(sqlbl, con=conn)
    return df

# 获取文件大小，以MB为单位
def get_FileSize(filePath):
    fsize = os.path.getsize(filePath)
    fsize = fsize/float(1024*1024)
    return round(fsize, 2)


def init_matrix(path):
    list_name = pd.Series()
    data1 = []

    data = get_ass()
    logger.info(data)
    data = data.values
    for i in data:
        # print(i[2])
        # print(findtype(i[2]))
        # exit(0)
        try:
            Atype = i[2]
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
    # 将告警日志数据转化为csv，用于判断其大小
    data.to_csv("./result/data.csv", index_label="dataId")
    logSize = get_FileSize('./result/data.csv')
    logger.info("IDS log size is %.2f" % logSize)
    if logSize > 500:
        logger.info("IDS log size is too large! Can't analysis!")
        exit(0)

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
