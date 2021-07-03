from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from weather import get_weather
from functools import wraps
import numpy as np
import datetime
import pickle
import uuid
import jwt


app = Flask(__name__)

app.config['SECRET_KEY'] = 'hiinisiri' #to be added to env vars
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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' :'token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], options={"verify_signature": False})
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
           return jsonify({'message': 'The token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

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
@token_required
def get_all_user(current_user):

    users = User.query.all()
    if not users:
        return jsonify({'message' : 'No users found'})

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
@token_required
def get_one_user(current_user, user_id):
    user = User.query.filter_by(public_id = user_id).first()

    if not user:
        return jsonify({'message' : 'User does not exist'})
   
    output = []

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['username'] = user.username
    user_data['phonenumber'] = user.phonenumber
    output.append(user_data)
    return jsonify({'user' : output})

@app.route('/user/<user_id>', methods = ['PUT'])
@token_required
def modify_user(current_user):
    return ''

@app.route('/user/<user_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, user_id):
    user = User.query.filter_by(public_id = user_id).first()

    if not user:
        return jsonify({'message' : 'User does not exist'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'User deleted succesfully'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required'})

    user = User.query.filter_by(username = auth.username).first()
    
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required'})    

@app.route('/predict', methods = ['POST'])
@token_required
def predict(current_user):
    data = request.get_json()
    N = data['N']
    P = data['P']
    K = data['K']
    pH = data['pH']
    rainfall = data['rainfall']
    temperature, humidity = get_weather(data['city'])

    model_path = 'model.pkl'
    model = pickle.load(open(model_path, 'rb'))

    data = np.array([[N, P, K, temperature, humidity, pH, rainfall]])
    prediction = model.predict(data)
    prediction = prediction[0]

    return jsonify({'prediction': prediction})

# {"N":10 ,"P": 55,"K": 23,"pH": 5.728,"rainfall": 137,"city" : "kikuyu"}

if __name__ == '__main__':
    app.run(debug=True)