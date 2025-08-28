# -*- coding: utf-8 -*-
# @Date       : 2025-08-21
# @Time       : 2025/8/21:10:19
# @Author     : ARotterGoodMan
# @File       : SERVER.py
# @ProjectName: BlogApi

import bcrypt
import uuid, os
from gmssl import sm2
from src import function as func, SendEmail


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
    if hashed == '':
        sql = "DELETE FROM sm2_keys WHERE key_id = %s"
        func.execute_query(sql, (key_id,))
        return response(200, "密码解密完成", {"password": password})

    if not bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8")):
        return response(401, "密码不正确")
    sql = "DELETE FROM sm2_keys WHERE key_id = %s"
    func.execute_query(sql, (key_id,))
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
    sql = "SELECT user_id, username, password, email, Admin,max_logins FROM Users WHERE email = %s"
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
    if len(login_data) >= select_data[5]:
        return response(403, "设备已到达登录上线，请先注销一个设备后再登录")

    sql = "INSERT INTO Login (user_id, token, ip_address) VALUES (%s, %s, %s)"
    token = str(uuid.uuid4())
    func.execute_query(sql, (select_data[0], token, data["ip_address"]))

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
    sql = "SELECT user_id FROM Users WHERE email = %s"
    existing_user = func.fetchone(sql, (data["email"],))
    if existing_user:
        return response(409, "用户已存在")
    sql = "SELECT user_id FROM Users"
    all_users = func.fetchall(sql)

    if not all_users:
        user_id = "0001"
        data['Admin'] = 2  # 第一个注册的用户为管理员
    else:
        user_id = str(int(max(u[0] for u in all_users)) + 1).zfill(4)

    checkPassword = check_password(data['key_id'], data["password"], '')["data"]["password"]
    data['password'] = checkPassword

    hashed_password = hash_password(data["password"])
    sql = "INSERT INTO Users (user_id,username,password,email,Admin) VALUES (%s,%s, %s, %s,%s)"
    func.execute_query(sql,
                       (user_id, data["username"], hashed_password, data["email"],
                        data['Admin'] if 'Admin' in data else 0))
    return response(201, "用户注册成功")


def getAllUsers(token):
    is_admin = isAdmin(token)
    if is_admin["status"] != 200:
        return is_admin

    sql = "SELECT user_id, username, email, Admin ,max_logins FROM Users"
    users = func.fetchall(sql)
    if not users:
        return response(404, "没有找到用户")

    user_list = [{"id": u[0], "username": u[1], "email": u[2], "is_admin": int(u[3]), "max_logins": u[4]} for u in
                 users]
    return response(200, "获取用户列表成功", user_list)


def updateUser(token, data):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]

    # 检查是否允许修改别人
    target_id = data.get("id", user_id)
    if target_id != user_id:
        sql = "SELECT Admin FROM Users WHERE user_id = %s"
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
        checkPassword = check_password(data['key_id'], data["password"], "")
        hashed = hash_password(checkPassword["data"]["password"])
        update_fields.append("password = %s")
        values.append(hashed)
        sql = "DELETE FROM sm2_keys WHERE key_id = %s"
        func.execute_query(sql, (data['key_id'],))

    if "Admin" in data:
        update_fields.append("Admin = %s")
        values.append(int(data["Admin"]))
    if "max_logins" in data:
        update_fields.append("max_logins = %s")
        values.append(int(data["max_logins"]))

    if not update_fields:
        return response(400, "没有提供要更新的信息")

    values.append(target_id)
    sql = f"UPDATE Users SET {', '.join(update_fields)} WHERE user_id = %s"
    func.execute_query(sql, tuple(values))
    return response(200, "用户信息更新成功")


def deleteUser(token, data):
    is_admin = isAdmin(token)
    if is_admin["status"] != 200:
        return is_admin
    print(data)
    if "id" not in data:
        return response(400, "id是必需的")
    sql = "SELECT id FROM Users WHERE id = %s"
    target_user = func.fetchone(sql, (data["id"],))
    if not target_user:
        return response(404, "未找到目标用户")
    sql = "DELETE FROM Users WHERE id = %s"
    func.execute_query(sql, (data["id"],))
    sql = "DELETE FROM Login WHERE user_id = %s"
    func.execute_query(sql, (data["id"],))
    return response(200, "用户删除成功")


def get_profile(token):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]
    sql = "SELECT * FROM UserProfile WHERE user_id = %s"
    user = func.fetchone(sql, (user_id,))
    if not user:
        return response(404, "您还没有填写个人信息")

    user_info = {
        "name": user[2],
        "sex": user[3],
        "birth_date": user[4],
        "phone": user[5],
        "address": user[6],
        "city": user[7],
        "province": user[8],
        "postal_code": user[9]
    }

    return response(200, "获取个人信息成功", user_info)


def update_profile(token, data):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]

    # 检查是否存在用户信息
    sql = "SELECT id FROM UserProfile WHERE user_id = %s"
    existing_profile = func.fetchone(sql, (user_id,))

    if not existing_profile:
        # 插入新记录
        sql = f"INSERT INTO UserProfile (user_id, name,sex,birth_date,phone,address,city,province,postal_code) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        func.execute_query(
            sql,
            (user_id,
             data['name'] if 'name' in data else '',
             data["sex"] if 'sex' in data else '保密',
             data["birth_date"] if 'birth_date' in data else None,
             data["phone"] if 'phone' in data else '',
             data["address"] if 'address' in data else '',
             data["city"] if 'city' in data else '',
             data["province"] if 'province' in data else '',
             data["postal_code"] if 'postal_code' in data else ''
             )
        )
    else:
        # 更新现有记录
        update_fields = []
        values = []
        if "name" in data:
            update_fields.append("name = %s")
            values.append(data["name"])
        if "sex" in data:
            update_fields.append("sex = %s")
            values.append(data["sex"])
        if "birth_date" in data:
            update_fields.append("birth_date = %s")
            values.append(data["birth_date"])
        if "phone" in data:
            update_fields.append("phone = %s")
            values.append(data["phone"])
        if "address" in data:
            update_fields.append("address = %s")
            values.append(data["address"])
        if "city" in data:
            update_fields.append("city = %s")
            values.append(data["city"])
        if "country" in data:
            update_fields.append("province = %s")
            values.append(data["province"])
        if "postal_code" in data:
            update_fields.append("postal_code = %s")
            values.append(data["postal_code"])
        if not update_fields:
            return response(400, "没有提供要更新的信息")
        values.append(user_id)
        sql = f"UPDATE UserProfile SET {', '.join(update_fields)} WHERE user_id = %s"
        func.execute_query(sql, tuple(values))

    return {"status": 200, "message": "个人信息更新成功"}


def get_notes(token):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]
    sql = "SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = %s"
    notes = func.fetchall(sql, (user_id,))
    if not notes:
        return response(404, "没有找到笔记")

    note_list = [
        {"id": n[0],
         "title": n[1],
         "content": n[2],
         "created_at": str(n[3]),
         "updated_at": str(n[4])
         } for n in notes
    ]
    return response(200, "获取笔记成功", note_list)


def create_or_update_note(token, data):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]

    if "title" not in data or "content" not in data:
        return response(400, "标题和内容是必需的")

    sql = "SELECT id FROM notes WHERE id = %s AND user_id = %s"
    sel = func.fetchone(sql, (data.get("id", ""), user_id))
    if "id" in data and sel:
        sql = "UPDATE notes SET title = %s, content = %s, updated_at = NOW() WHERE id = %s AND user_id = %s"
        func.execute_query(sql, (data["title"], data["content"], data["id"], user_id))
        return response(200, "笔记更新成功")
    else:
        # 创建新笔记
        note_id = str(uuid.uuid4())
        sql = "INSERT INTO notes (id,user_id, title, content) VALUES (%s,%s, %s, %s)"
        func.execute_query(sql, (note_id, user_id, data["title"], data["content"]))
        return response(201, "创建笔记成功")


def delete_note(token, note_id):
    check_token = checkToken(token)
    if check_token["status"] != 200:
        return check_token
    user_id = check_token["data"]["user_id"]

    sql = "SELECT id FROM notes WHERE id = %s AND user_id = %s"
    note = func.fetchone(sql, (note_id, user_id))
    if not note:
        return response(404, "未找到目标笔记")

    sql = "DELETE FROM notes WHERE id = %s AND user_id = %s"
    func.execute_query(sql, (note_id, user_id))
    return response(200, "笔记删除成功")


def forgot_password(data):
    email = data.get("email")
    if not email:
        return response(404, "email是必需的")
    sql = "SELECT id, username FROM Users WHERE email = %s"
    user = func.fetchone(sql, (email,))
    if not user:
        return response(404, "未找到用户")
    user_id, username = user
    # 生成重置令牌
    reset_token = str(uuid.uuid4())
    user_id = str(user_id).zfill(4)
    sql = "INSERT INTO PasswordResets (user_id, reset_token) VALUES (%s, %s)"
    func.execute_query(sql, (user_id, reset_token))
    reset_link = f"http://localhost:5173/reset-password?token={reset_token}"
    test.send_reset_email(email, reset_link)
    return response(200, "重置密码邮件已发送，请检查您的邮箱")


def reset_password(data):
    reset_token = data.get("token")
    new_password = data.get("new_password")
    if not reset_token or not new_password:
        return response(400, "token和新密码是必需的")
    sql = "SELECT user_id FROM PasswordResets WHERE reset_token = %s"
    reset_record = func.fetchone(sql, (reset_token,))
    if not reset_record:
        return response(404, "无效的重置令牌")
    user_id = reset_record[0]
    checkPassword = check_password(data['key_id'], new_password, "")["data"]["password"]
    hashed_password = hash_password(checkPassword)
    sql = "UPDATE Users SET password = %s WHERE user_id = %s"
    func.execute_query(sql, (hashed_password, user_id))
    sql = "DELETE FROM PasswordResets WHERE reset_token = %s"
    func.execute_query(sql, (reset_token,))
    return response(200, "重置密码成功")
