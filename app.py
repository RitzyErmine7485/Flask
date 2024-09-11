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
        return jsonify({"msg": "Ese usuario ya existe"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({"username":username,"email":email,"password": hashed_password})
    if result.acknowledged:
        return jsonify({"msg": "Usuario Creado Correctamente"}), 201
    else:
        return jsonify({"msg": "Hubo un error, no se pudieron guardar los datos"}),400

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
        return jsonify({'msg': 'Credenciales incorrectas'}), 401

@app.route('/data', methods=['POST'])
@jwt_required()
def datos():
    data = request.get_json()
    username = data.get('username')

    usuario = mongo.db.users.find_one({'username': username}, {'password': 0})

    if usuario:
        usuario['_id'] = str(usuario['_id'])
        return jsonify({'msg': 'Usuario encontrado', 'Usuario': usuario}), 200
    else:
        return jsonify({'msg': 'Usuario no encontrado'}), 404

if __name__ == '__main__':
    app.run(debug=True)