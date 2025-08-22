# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:24
# @Author     : ARotterGoodMan
# @File       : SERVER.py
# @ProjectName: BlogApi

import uuid
from hashlib import md5
from src import function as func


def checkToken(token):
    if not token:
        return {'status': 400, 'message': 'token是必需的'}
    sql = f"SELECT user_id FROM Login WHERE token = '{token}'"
    login_data = func.fetchone(sql)
    if not login_data:
        return {'status': 404, 'message': '未找到登录记录'}
    return {
        'status': 200,
        'message': 'token验证成功',
        'data': {
            'user_id': login_data[0]
        }
    }


def login(data):
    sql = f"SELECT id,username,password,salt,email,Admin FROM Users WHERE " \
          f"email = '{data['email']}'"

    select_data = func.fetchone(sql)
    if select_data:
        if select_data[2] == md5((data['password'] + select_data[3]).encode('utf-8')).hexdigest():
            # 检查设备是否已登录
            sql = f"SELECT token FROM Login WHERE user_id = {select_data[0]}"
            login_data = func.fetchall(sql)
            if len(login_data) >= 3:
                return {'status': 403, 'message': '设备已到达登录上线. 请先注销一个设备后再登录'}
            token = str(uuid.uuid4())
            sql = f"insert into Login (user_id, token,ip_address) values ({select_data[0]}, '{token}','{data['ip_address']}')"
            func.execute_query(sql)
            return {
                'status': 200,
                'message': '登录成功',
                'data': {
                    'username': select_data[1],
                    'email': select_data[4],
                    'is_admin': select_data[5],
                    "token": token
                }
            }
        else:
            return {'status': 401, 'message': '密码不正确'}
    else:
        return {'status': 404, 'message': '未找到用户'}


def logout(data):
    check_token = checkToken(data['token'])
    if check_token['status'] != 200:
        return check_token
    sql = f"SELECT id FROM Login WHERE token = '{data['token']}'"
    login_data = func.fetchone(sql)
    if not login_data:
        return {'status': 404, 'message': '未找到登录记录'}
    sql = f"DELETE FROM Login WHERE token = '{data['token']}'"
    func.execute_query(sql)
    return {'status': 200, 'message': '注销成功'}


def register(data):
    sql = f"SELECT 'email' FROM Users WHERE email = '{data['email']}'"
    existing_user = func.fetchone(sql)
    if existing_user:
        return {'status': 409, 'message': '用户已存在'}

    salt = str(uuid.uuid4())
    password = data['password'] + salt
    password = password.encode('utf-8')

    hashed_password = md5(password).hexdigest()

    sql = f"INSERT INTO Users (username, password, salt, email) VALUES " \
          f"('{data['username']}', '{hashed_password}', '{salt}', '{data['email']}')"

    func.execute_query(sql)

    return {'status': 201, 'message': '用户注册成功'}


def getAllUsers(token):
    check_token = checkToken(token)
    if check_token['status'] != 200:
        return check_token
    user_id = check_token['data']['user_id']
    sql = f"SELECT Admin FROM Users WHERE id = {user_id}"
    user_data = func.fetchone(sql)
    if not user_data or not user_data[0]:
        return {'status': 403, 'message': '权限不足'}
    sql = "SELECT id, username, email,Admin FROM Users"
    users = func.fetchall(sql)
    if not users:
        return {'status': 404, 'message': '没有找到用户'}

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'is_admin': user[3]
        })

    return {'status': 200, 'message': '获取用户列表成功', 'data': user_list}


def resetPassword(data):
    pass


# 修改用户信息
def updateUser(token, data):
    check_token = checkToken(token)
    if check_token['status'] != 200:
        return check_token

    user_id = check_token['data']['user_id']
    sql = f"SELECT Admin FROM Users WHERE id = {user_id}"
    user_data = func.fetchone(sql)
    if 'id' in data and data['id'] != user_id:
        sql = f"SELECT Admin FROM Users WHERE id = {user_id}"
        target_user_data = func.fetchone(sql)
        if not target_user_data or not target_user_data[0]:
            return {'status': 403, 'message': '权限不足'}
    update_fields = []
    if 'username' in data:
        update_fields.append(f"username = '{data['username']}'")
    if 'email' in data:
        update_fields.append(f"email = '{data['email']}'")
    if "password" in data:
        salt = str(uuid.uuid4())
        password = data['password'] + salt
        password = password.encode('utf-8')
        hashed_password = md5(password).hexdigest()
        update_fields.append(f"password = '{hashed_password}'")
        update_fields.append(f"salt = '{salt}'")
    if "Admin" in data:
        update_fields.append(f"Admin = {int(data['Admin'])}")
    if not update_fields:
        return {'status': 400, 'message': '没有提供要更新的信息'}

    sql = f"UPDATE Users SET {', '.join(update_fields)} WHERE id = {
    (data['id']) if 'id' in data else user_id
    }"
    func.execute_query(sql)

    return {'status': 200, 'message': '用户信息更新成功'}


def deleteUser(token, data):
    check_token = checkToken(token)
    if check_token['status'] != 200:
        return check_token

    user_id = check_token['data']['user_id']
    sql = f"SELECT Admin FROM Users WHERE id = {user_id}"
    user_data = func.fetchone(sql)
    if not user_data or not user_data[0]:
        return {'status': 403, 'message': '权限不足'}
    if 'user_id' not in data:
        return {'status': 400, 'message': 'user_id是必需的'}
    sql = f"SELECT id FROM Users WHERE id = {data['user_id']}"
    target_user = func.fetchone(sql)
    if not target_user:
        return {'status': 404, 'message': '未找到目标用户'}
    sql = f"DELETE FROM Users WHERE id = {data['user_id']}"
    func.execute_query(sql)
    sql = f"DELETE FROM Login WHERE user_id = {data['user_id']}"
    func.execute_query(sql)
    return {'status': 200, 'message': '用户删除成功'}
