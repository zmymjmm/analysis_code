import uuid
import csv
import pandas as pd
from dbConnect import *
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 将字符串中的空格替换为"_"
def replaceSpace(s):
    l = list(s)
    for i in range(len(l)):
        if l[i] == ' ':
            l[i] = '_'
    return ''.join(l)

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
    end_time = "2021-11-12"
    sqlbl = "select id,time,logstr,src_ip,dst_ip from topic3_event where time between '%s' and '%s'" % (begin_time, end_time)
    df = pd.read_sql_query(sqlbl, con=conn)
    return df

if __name__ == '__main__':

    # 如果三个结果文件存在则删除
    if os.path.exists('./result/event_list.csv'):
        os.remove('./result/event_list.csv')

    if os.path.exists('./result/finallsit.txt'):
        os.remove('./result/finallsit.txt')

    if os.path.exists('./result/process_list.csv'):
        os.remove('./result/process_list.csv')

    df = get_ass()
    # print(df)
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
        dattack = df.loc[frame_index, 'dst_ip'].tolist()[0]
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

    # 重复连接数据库，直到连接成功才进行下一步操作
    while 1 == 1:
        try:
            conn = connect(logger)
            logger.info('Successful connect the database')
            break
        except:
            logger.info('reconnect the database')
    cursor = conn.cursor()

    # 往topic3_backlog表插入数据
    df = pd.read_csv('./result/event_list.csv', encoding='UTF-8', names = ['id', 'datetime',' risk_level', 'src_ip', 'dst_ip', 'level'])
    print(df)
    # 插入前清空表
    sqlal = "DELETE FROM topic3_backlog"
    cursor.execute(sqlal)
    conn.commit()
    lst = df.values.tolist()
    for i in lst:
        sqlbl = "INSERT INTO topic3_backlog values('%s','%s','%s',%s,'%s','%s','%s')" % (str(i[0]), str(i[1]), str(i[2]), 40, str(i[3]), str(i[4]), str(i[5]))
        cursor.execute(sqlbl)
        conn.commit()
        print('Success insert a record!')

    # 往topic3_backlog_event表插入数据
    df = pd.read_csv('./result/process_list.csv', encoding='UTF-8', names=['backlog_id', 'event_id', 'process', 'killline'])
    print(df)
    # 插入前清空表
    sqlal = "DELETE FROM topic3_backlog_event"
    cursor.execute(sqlal)
    conn.commit()
    lst = df.values.tolist()
    for i in lst:
        sqlbl = "INSERT INTO topic3_backlog_event values('%s',%s,%s,%s)" % (str(i[0]), int(i[1]), int(i[2]), int(i[3]))
        cursor.execute(sqlbl)
        conn.commit()
        print('Success insert a record!')

    cursor.close()
    conn.close()