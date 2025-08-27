# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:19
# @Author     : ARotterGoodMan
# @File       : function.py
# @ProjectName: BlogApi

import pymysql


def connect():
    return pymysql.connect(
        host="",
        port=3306,
        user="",
        password="",
        database="",
    )


def execute_query(query, params=None):
    with connect() as con:
        with con.cursor() as cur:
            cur.execute(query, params)
        con.commit()


def fetchone(query, params=None):
    with connect() as con:
        with con.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()


def fetchall(query, params=None):
    with connect() as con:
        with con.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()
