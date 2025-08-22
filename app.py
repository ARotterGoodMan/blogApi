from flask import Flask, request
from hashlib import md5

from flask_cors import CORS

from src import SERVER

app = Flask(__name__)

CORS(app, resources={r'/*': {"origins": ["http://127.0.0.1:5173", "http://localhost:5173"]}})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400

    # Placeholder for login logic
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
    if  not data:
        return {"error": "No data provided"}, 400
    return SERVER.updateUser(token, data)


@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    token = request.headers.get('Authorization')
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    return SERVER.deleteUser(token, data)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
