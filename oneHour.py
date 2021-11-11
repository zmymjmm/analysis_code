from insertTopci3Event import *
import time
import logging

def sleeptime(hour, min, sec):
    return hour*3600 + min*60 + sec

# 一个小时执行一次原始数据读取和插入
second = sleeptime(1, 0, 0)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

while 1 == 1:
    time.sleep(second)
    readAndInsert(logger)
    logger.info("insert success!")
    logger.info('__________________________hour_over__________________________')
