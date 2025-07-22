import pandas as pd
import matplotlib.pyplot as plt
import sqlite3 as lite
from sqlite3 import Error
from pathlib import Path
from datetime import date
import numpy as np
import seaborn as sns
import matplotlib.ticker as tick
import requests
import difflib as diff
import re
import csv
import ast
from sqlalchemy import create_engine, text
import os
import argparse
def parse_options():
    parser = argparse.ArgumentParser(description='Extracting data.')
    parser.add_argument('-i', '--input', help='The dir path of input', type=str)
    parser.add_argument('-o', '--output', help='The dir path of output', type=str)
    args = parser.parse_args()
    return args

def mkdir(path):
    folder = os.path.exists(path)

    if not folder:
        os.makedirs(path)
        print(path, "文件夹创建成功")


    else:
        print(path, "已存在")


def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    conn = None
    try:
        conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
        # engine = sa.create_engine('sqlite:///' + db_file)  # connection via sqlalchemy
        # conn = engine.connect()
        print("连接数据库成功")
    except Error as e:
        print(e)
    return conn


if __name__ == '__main__':
    args = parse_options()
    DATA_PATH = args.input #the address of CVEfixes database
    RESULT_PATH = args.output
    #DATA_PATH = 'D:\share\CVEfixes_v1.0.7\Data\CVEfixes.db'
    #RESULT_PATH = 'D:\CVEfixes'
    Path(RESULT_PATH).mkdir(parents=True, exist_ok=True)

    conn = create_connection(DATA_PATH)
    query = '''
  SELECT cc.cwe_id, r.repo_name, cv.cve_id, f.hash, f.filename, f.code_before, f.code_after, f.diff
FROM file_change f, commits c, fixes fx, cve cv, cwe_classification cc, repository r
WHERE (f.programming_language = 'C' OR f.programming_language = 'C++')
AND f.hash = c.hash 
AND c.hash = fx.hash 
AND fx.cve_id = cv.cve_id 
AND cv.cve_id = cc.cve_id
AND r.repo_url = c.repo_url
AND (f.filename LIKE '%.c' OR f.filename LIKE '%.cpp' OR f.filename LIKE '%.cc');
    '''
    num = 0
    result = conn.execute(query)
    for row in result.fetchall():
        cwe_id = row[0]
        repo_name = row[1]
        if '/' in repo_name:
            sub_str = repo_name[repo_name.index('/') + 1:]
            print(sub_str)
        else:
            sub_str = repo_name
        cve_id = row[2]
        hAsh = row[3]
        file_name = row[4]
        sub_str = sub_str.replace(" ", "_")
        OLD = row[5]
        NEW = row[6]
        diff = row[7]
        mkdir(RESULT_PATH + '\\' + cwe_id)
        mkdir(RESULT_PATH + '\\' + cwe_id + '\\' + sub_str)
        mkdir(RESULT_PATH + '\\' + cwe_id + '\\' + sub_str + '\\' + cve_id)
        pre_str = RESULT_PATH + '\\' + cwe_id + '\\' + sub_str + '\\' + cve_id + '\\' + cve_id + '_' + cwe_id + '_' +hAsh + '_' + file_name
        diff_name = pre_str + '.diff'
        NEW_name = pre_str + '_NEW.c'
        OLD_name = pre_str + '_OLD.c'

        with open(diff_name, 'w', encoding='utf-8') as file:
            file.write(diff)
            print(diff_name+"写入成功")
            num = num + 1
        with open(NEW_name, 'w', encoding='utf-8') as file:
            file.write(NEW)
            print(NEW_name + "写入成功")
        with open(OLD_name, 'w', encoding='utf-8') as file:
            file.write(OLD)
            print(OLD_name + "写入成功")

    print(num)
