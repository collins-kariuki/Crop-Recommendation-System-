from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import uuid

app = Flask(__name__)

app.config['SECRET_KEY'] = 'hiinisiri'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////database.db'

db = SQLAlchemy(app)

#Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(80))
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(256))
    phonenumber = db.Column(db.String(20))

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nitrogen = db.Column(db.Integer)
    phosphorus = db.Column(db.Integer)
    potassium = db.Column(db.Integer)
    pH = db.Column(db.Integer)
    predicted = db.Column(db.String(80))


@app.route("/")
def hello_world():
    return "Helo"

@app.route("/user",methods = ['POST'])
def create_user():
    data = request.get_json()

    hashed_pass = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_pass, phonenumber=data['phonenumber'], name=data['name'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'User created succesfully'})

@app.route('/user', methods = ['GET'])
def get_all_user():

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['username'] = user.username
        user_data['phonenumber'] = user.phonenumber
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<user_id>', methods =['GET'])
def get_one_user(user_id):
    user = User.query.filter_by(public_id = user_id).first()

    output = []

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['username'] = user.username
    user_data['phonenumber'] = user.phonenumber
    output.append(user_data)
    return jsonify({'user' : output})

@app.route('/user/<user_id>', methods = ['PUT'])
def modify_user():
    return ''

@app.route('/user/<user_id>', methods = ['DELETE'])
def delete_user():
    return ''

if __name__ == '__main__':
    app.run(debug=True)