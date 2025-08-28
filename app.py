from flask import Flask, request
from flask_cors import CORS
from src import SERVER
from src.config import origins

app = Flask(__name__)

CORS(app, resources={
    r'/*': {"origins": origins}})


@app.post("/api/generate_keys")
def generate_keys():
    return SERVER.generate_sm2_keypair()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400

    return SERVER.login(data)


@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    if not token:
        return {"error": "No token provided"}, 400
    data = {'token': token}
    # Placeholder for logout logic
    return SERVER.logout(data)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    # Placeholder for registration logic
    return SERVER.register(data)


@app.route('/api/get_all', methods=['Post'])
def get_all():
    token = request.headers.get('Authorization')
    return SERVER.getAllUsers(token)


@app.route('/api/updateUser', methods=['POST'])
def get_user():
    token = request.headers.get('Authorization')
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.updateUser(token, data)


@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    token = request.headers.get('Authorization')
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.deleteUser(token, data)


# 个人信息
@app.route("/api/get_profile", methods=["POST"])
def get_profile():
    token = request.headers.get('Authorization')
    return SERVER.get_profile(token)


@app.route("/api/update_profile", methods=["POST"])
def update_profile():
    token = request.headers.get('Authorization')
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.update_profile(token, data)


@app.route("/api/forgot_password", methods=["POST"])
def forgot_password():
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.forgot_password(data)


@app.route("/api/reset_password", methods=["POST"])
def reset_password():
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.reset_password(data)


@app.route('/api/notes', methods=['GET', 'POST'])
def get_notes():
    method = request.method
    token = request.headers.get('Authorization')
    if method == 'GET':
        # 根据 token 获取用户的笔记
        return SERVER.get_notes(token)
    else:
        # 保存新笔记或修改笔记
        data = request.json
        if not data:
            return {"error": "No data provided"}, 400
        return SERVER.create_or_update_note(token, data)


# 删除单条笔记
@app.route('/api/del_notes/<note_id>', methods=['DELETE'])
def delete_note(note_id):
    token = request.headers.get('Authorization')
    return {"message": f"删除笔记 {note_id} 成功"}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
