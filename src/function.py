# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:19
# @Author     : ARotterGoodMan
# @File       : function.py
# @ProjectName: BlogApi

import pymysql


def connect():
    con = pymysql.connect(
        host="47.92.254.227",
        port=3306,
        user="sxy",
        password="Shao264419",
        database="MyBlog",
    )
    cur = con.cursor()
    return con, cur


def execute_query(query, params=None):
    con, cur = connect()
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)
    con.commit()
    cur.close()
    con.close()


def fetchone(query, params=None):
    con, cur = connect()
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)
    result = cur.fetchone()
    cur.close()
    con.close()
    return result


def fetchall(query):
    con, cur = connect()
    cur.execute(query)
    data = cur.fetchall()
    cur.close()
    con.close()
    return data
