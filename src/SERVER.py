# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:19
# @Author     : ARotterGoodMan
# @File       : SERVER.py
# @ProjectName: BlogApi

import uuid, os
import bcrypt
from gmssl import sm2
from src import function as func


def generate_sm2_keypair():
    private_key = os.urandom(32).hex()
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key='')
    public_key = sm2_crypt._kg(int(private_key, 16), sm2_crypt.ecc_table['g'])
    public_key = '04' + public_key  # 添加前缀04表示未压缩的公钥格式
    key_id = os.urandom(4).hex()
    sql = "INSERT INTO sm2_keys (key_id, private_key, public_key) VALUES (%s, %s, %s)"
    func.execute_query(sql, (key_id, private_key, public_key))

    return {"key_id": key_id, "public_key": public_key}


def response(status, message, data=None):
    return {"status": status, "message": message, "data": data}


def hash_password(password: str) -> str:
    """bcrypt 哈希密码"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(key_id, password: str, hashed: str) -> dict:
    """验证密码"""
    sql = "SELECT private_key, public_key FROM sm2_keys where key_id = %s"
    key_data = func.fetchone(sql, (key_id,))
    if not key_data:
        return response(500, "服务器密钥未配置，请联系管理员")
    privateKey, publicKey = key_data
    sm2_crypt = sm2.CryptSM2(public_key=publicKey, private_key=privateKey)
    cipher_hex = password  # 前端 sm2.doEncrypt 生成的 hex 字符串
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
    except Exception as e:
        print("不是合法 hex:", e)
        return response(500, "密文格式错误")
    plain_bytes = sm2_crypt.decrypt(cipher_bytes)
    password = plain_bytes.decode('utf-8')
    if not bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8")):
        return response(401, "密码不正确")
    return response(200, "密码正确")


def checkToken(token):
    if not token:
        return response(400, "token是必需的")

    sql = "SELECT user_id FROM Login WHERE token = %s"
    login_data = func.fetchone(sql, (token,))
    if not login_data:
        return response(404, "未找到登录记录")

    return response(200, "token验证成功", {"user_id": login_data[0]})


def isAdmin(token, require_level=1):
    """
    require_level = 1 表示至少是管理员
    require_level = 2 表示必须是超级管理员
    """
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token

    user_id = check_token["data"]["user_id"]
    sql = "SELECT Admin FROM Users WHERE id = %s"
    user_data = func.fetchone(sql, (user_id,))
    if not user_data:
        return response(404, "未找到用户")

    if int(user_data[0]) >= require_level:
        return response(200, "权限验证通过")
    return response(403, "权限不足")


def login(data):
    sql = "SELECT id, username, password, email, Admin FROM Users WHERE email = %s"
    select_data = func.fetchone(sql, (data["email"],))
    check_password_over = check_password(data['key_id'], data["password"], select_data[2])
    if check_password_over["status"] != 200:
        return check_password_over

    if not select_data:
        return response(404, "未找到用户")

    if not check_password(data['key_id'], data["password"], select_data[2]):
        return response(401, "密码不正确")

    # 检查设备数
    sql = "SELECT token FROM Login WHERE user_id = %s"
    login_data = func.fetchall(sql, (select_data[0],))
    if len(login_data) >= 3:
        return response(403, "设备已到达登录上线，请先注销一个设备后再登录")

    token = str(uuid.uuid4())
    sql = "INSERT INTO Login (user_id, token, ip_address) VALUES (%s, %s, %s)"
    func.execute_query(sql, (select_data[0], token, data["ip_address"]))
    sql = "DELETE FROM sm2_keys WHERE key_id = %s"
    func.execute_query(sql, (data['key_id'],))

    return response(200, "登录成功", {
        "username": select_data[1],
        "email": select_data[3],
        "is_admin": int(select_data[4]),
        "token": token
    })


def logout(data):
    check_token = checkToken(data["token"])
    if check_token["status"] != 200:
        return check_token

    sql = "DELETE FROM Login WHERE token = %s"
    func.execute_query(sql, (data["token"],))
    return response(200, "注销成功")


def register(data):
    sql = "SELECT id FROM Users WHERE email = %s"
    existing_user = func.fetchone(sql, (data["email"],))
    if existing_user:
        return response(409, "用户已存在")

    hashed_password = hash_password(data["password"])
    sql = "INSERT INTO Users (username, password, email,Admin) VALUES (%s, %s, %s,%s)"
    func.execute_query(sql,
                       (data["username"], hashed_password, data["email"], data['Admin'] if 'Admin' in data else 0))

    return response(201, "用户注册成功")


def getAllUsers(token):
    is_admin = isAdmin(token)
    if is_admin["status"] != 200:
        return is_admin

    sql = "SELECT id, username, email, Admin FROM Users"
    users = func.fetchall(sql)
    if not users:
        return response(404, "没有找到用户")

    user_list = [{"id": u[0], "username": u[1], "email": u[2], "is_admin": int(u[3])} for u in users]
    return response(200, "获取用户列表成功", user_list)


def updateUser(token, data):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]

    # 检查是否允许修改别人
    target_id = data.get("id", user_id)
    if target_id != user_id:
        sql = "SELECT Admin FROM Users WHERE id = %s"
        admin_flag = func.fetchone(sql, (user_id,))
        if not admin_flag or int(admin_flag[0]) != 1:
            return response(403, "权限不足")

    update_fields = []
    values = []

    if "username" in data:
        update_fields.append("username = %s")
        values.append(data["username"])
    if "email" in data:
        update_fields.append("email = %s")
        values.append(data["email"])
    if "password" in data:
        hashed = hash_password(data["password"])
        update_fields.append("password = %s")
        values.append(hashed)
    if "Admin" in data:
        update_fields.append("Admin = %s")
        values.append(int(data["Admin"]))

    if not update_fields:
        return response(400, "没有提供要更新的信息")

    values.append(target_id)
    sql = f"UPDATE Users SET {', '.join(update_fields)} WHERE id = %s"
    func.execute_query(sql, tuple(values))
    return response(200, "用户信息更新成功")


def deleteUser(token, data):
    is_admin = isAdmin(token)
    if is_admin["status"] != 200:
        return is_admin
    if "user_id" not in data:
        return response(400, "user_id是必需的")
    sql = "SELECT id FROM Users WHERE id = %s"
    target_user = func.fetchone(sql, (data["user_id"],))
    if not target_user:
        return response(404, "未找到目标用户")
    sql = "DELETE FROM Users WHERE id = %s"
    func.execute_query(sql, (data["user_id"],))
    sql = "DELETE FROM Login WHERE user_id = %s"
    func.execute_query(sql, (data["user_id"],))
    return response(200, "用户删除成功")
