# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:24
# @Author     : ARotterGoodMan
# @File       : SERVER.py
# @ProjectName: BlogApi

import uuid
from hashlib import md5

from src import function as func


def login(data):
    if data['email']:
        sql = f"SELECT id,username,password,salt,email,phone,Admin,token FROM Users WHERE " \
              f"email = '{data['email']}'"
    elif data['phone']:
        sql = f"SELECT id,username,password,salt,email,phone,Admin,token FROM Users WHERE " \
              f"phone= '{data['phone']}'"
    select_data = func.fetchone(sql)
    if select_data:
        # if select_data[7] and select_data[7] != 'null':
        #     return {'status': 403, 'message': 'User already logged in'}
        if select_data[2] == md5((data['password'] + select_data[3]).encode('utf-8')).hexdigest():
            token = str(uuid.uuid4())
            sql = f"UPDATE Users SET token = '{token}' WHERE id = {select_data[0]}"
            func.execute_query(sql)
            return {
                'status': 200,
                'message': 'Login successful',
                'data': {
                    'username': select_data[1],
                    'email': select_data[4],
                    'phone': select_data[5],
                    'is_admin': select_data[6],
                    "token": token
                }
            }
        else:
            return {'status': 401, 'message': 'Incorrect password'}
    else:
        return {'status': 404, 'message': 'User not found'}


def logout(data):
    if not data or 'token' not in data:
        return {'status': 400, 'message': 'Token is required'}

    # 使用参数化查询查找用户
    sql = "SELECT id, token FROM Users WHERE token=%s"
    select_data = func.fetchone(sql, (data['token'],))
    print(select_data)
    if select_data:
        # 使用参数化查询更新
        user_id = select_data[0]  # 假设第一列是id
        sql = "UPDATE Users SET token=NULL WHERE id=%s"
        func.execute_query(sql, (user_id,))
        return {
            'status': 200,
            'message': 'Logout successful'
        }
    return {
        'status': 404,
        'message': 'User not found or already logged out'
    }

    def register(data):
        sql = f"SELECT 'email' FROM Users WHERE email = '{data['email']}' or phone= '{data['phone']}'"
        existing_user = func.fetchone(sql)
        if existing_user:
            return {'status': 409, 'message': 'User already exists'}

        salt = str(uuid.uuid4())
        password = data['password'] + salt
        password = password.encode('utf-8')

        hashed_password = md5(password).hexdigest()

        sql = f"INSERT INTO Users (username, password, salt, email, phone) VALUES " \
              f"('{data['username']}', '{hashed_password}', '{salt}', '{data['email']}', '{data['phone']}')"

        func.execute_query(sql)

        return {'status': 201, 'message': 'User registered successfully'}
