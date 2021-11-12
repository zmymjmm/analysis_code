import pymysql

#  连接数据库
def connect(logger):
    conn = pymysql.connect(
        host='172.16.39.128',
        user='root',
        password='123456',
        db='alienvault_siem',
        charset='utf8'
    )
    return conn