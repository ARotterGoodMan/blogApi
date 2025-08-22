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


if __name__ == '__main__':
    # print(md5(("Shao264419" + "6a8497d2-6231-4bf9-b3c5-2d89b1b22f50").encode('utf-8')).hexdigest())
    app.run(host='0.0.0.0', port=5000, debug=True)
