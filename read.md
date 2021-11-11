### 关联分析

#### code

##### IPtest.py

读取日志，进行去重和聚类，根据杀伤链和因果关系关联分析，输出攻击链。

在分析过程中读取tempkillline.txt中的杀伤链，读取mat_new.txt中的转移矩阵。

结果分别为：**finallsit.txt、process_list.csv、event_list.csv**

##### finallist.txt

里面是分析出的攻击链

##### process_list.csv

对应*北邮结果字段说明* 文件中的攻击链关联字段说明

##### event_list.csv

对应*北邮结果字段说明* 文件中的攻击链事件说明

##### Keytest.py

生成概率转移矩阵，并将结果输入到mat_new.txt

