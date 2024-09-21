from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import mongo, init_db
from config import Config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "User already exists"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({"username": username,"email": email,"password": hashed_password, "score": 0})
    if result.acknowledged:
        return jsonify({"msg": "Success: User created successfully"}), 201
    else:
        return jsonify({"msg": "Error: Couldn't save the data"}),400

@app.route('/data', methods=['POST'])
@jwt_required()
def datos():
    data = request.get_json()
    username = data.get('username')

    usuario = mongo.db.users.find_one({'username': username}, {'password': 0})

    if usuario:
        usuario['_id'] = str(usuario['_id'])
        return jsonify({'msg': 'User found:', 'User': usuario}), 200
    else:
        return jsonify({'msg': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/update', methods=['POST'])
@jwt_required()
def update():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    new_username = data.get('new_username')
    new_password = data.get('new_password')

    user = mongo.db.users.find_one({'email': email})

    if user and bcrypt.check_password_hash(user['password'], password):
        if new_username:
            mongo.db.users.update_one(user, {'$set': { 'username': new_username } })
        elif new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            mongo.db.users.update_one(user, {'$set': { 'password': hashed_password } })
        else:
            return jsonify({'msg': 'Error: No update fields provided'}), 400
        
        return jsonify({'msg': 'Success: User information updated successfully'}), 200
    else:
        return jsonify({'msg': 'Error: Incorrect credentials'}), 401

@app.route('/delete', methods=['POST'])
@jwt_required()
def delete():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one_and_delete({'email': email})

    if user and bcrypt.check_password_hash(user['password'], password):
        return jsonify('Success: User deleted successfully'), 200
    else: 
        return jsonify({'msg': 'Error: Incorret credentials'}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify(access_token=access_token), 200
    else: 
        return jsonify({'msg': 'Error: Incorrect credentials'}), 401

