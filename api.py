import os
from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta

# Initialize Flask and Api
app = Flask(__name__)
api = Api(app)

# Set config variables and Initialize SQLAlchemy
base_dir = os.path.abspath(os.path.dirname(__file__))
app.config["SECRET_KEY"] = "02440123a4e4da8adbbb69fecbaa1c53"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(base_dir, "neuroflow.db")
app.config["SQLALCHEMY_TRACK_MODIFCATIONS"] = False
db = SQLAlchemy(app)

class Users(db.Model):
    '''Table for storing users'''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False, unique=True)
    streak = db.Column(db.Integer, nullable=True, default=0)
    moods = db.relationship('Moods', backref='user', lazy=True)
    
    def __repr__(self):
        return f'User: {self.username}'

class Moods(db.Model):
    '''Table for storing user's moods'''
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'Mood on {self.created} was {self.rating}'

def token_required(f):
    '''Credits to Manthan Trivedi https://www.bacancytechnology.com/blog/flask-jwt-authentication'''
    '''Used to authenticate users after they have logged'''
    @wraps(f)
    def decorator(self, *args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator

class User(Resource):
    def get(self):
        '''Gets all users when GET method at /user endpoint'''
        results = Users.query.all()
        if not results:
            return make_response(jsonify({'message': "No users in system"}), 404)

        users = []
        for result in results:
            user_data = {}
            user_data['username'] = result.username
            user_data['password'] = result.password
            user_data['streak'] = result.streak
            user_data['moods'] = []
            for mood in result.moods:
                mood_data = {}
                mood_data[mood.created.strftime("%m/%d/%Y, %H:%M:%S")] = mood.rating
                user_data['moods'].append(mood_data)
            users.append(user_data)

        res_status = 200
        response = jsonify({'Users': users})
        return make_response(response, res_status)

    def post(self):
        '''Creates a new user when /user endpoint is POSTed to'''
        data = request.get_json()
        results = Users.query.filter_by(username=data['username'])
        if results.count() > 0:
            message = "Username already exists"
            res_status = 403
        else:
            hashed_pass = generate_password_hash(data['password'], method="sha256")
            new_user = Users(username=data['username'], password=hashed_pass)
            db.session.add(new_user)
            db.session.commit()
            message = "New user created"
            res_status = 201
        res = jsonify({'message': message})
        return make_response(res, res_status)

class Login(Resource):
    def post(self):
        '''Login user when /login endpoint is POSTed to'''
        data = request.get_json()
        if not data or not "username" in data or not "password" in data:
            return make_response(jsonify({'message': "Missing username or password"}), 401)
        
        user = Users.query.filter_by(username=data['username']).first()
        
        if not user:
            return make_response(jsonify({"message": "Username does not exist"}), 401)
        elif not check_password_hash(user.password, data['password']):
            return make_response(jsonify({"message": "Wrong password"}), 401)
        
        token = jwt.encode({
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        response = jsonify({"message": "Logged in successfully", "token": token})
        return make_response(response, 200)

class Mood(Resource):
    @token_required
    def get(self):
        '''Get the current user's all their mood ratings and their current streak'''
        user_moods = []
        for mood in self.moods:
            mood_data = {}
            mood_data[mood.created.strftime("%m/%d/%Y, %H:%M:%S")] = mood.rating
            user_moods.append(mood_data)
        user_data = {
            "moods": user_moods,
            "streak": self.streak
        }
        response = jsonify({self.username: user_data})
        return make_response(response, 200)

    @token_required
    def post(self):
        '''Submits the current user's mood rating of the day'''
        data = request.get_json()
        if not "rating" in data:
            return make_response(jsonify({"message": "Rating is required to submit mood"}), 400)
        
        if data['rating'] > 5 or data['rating'] < 0:
            return make_response(jsonify({"message": "Rating must be 0 - 5"}), 400)
        
        latest_mood_submitted = Moods.query.filter_by(user_id=self.id).order_by(Moods.created.desc()).first()
        
        mood_created = datetime.utcnow() + timedelta(days=6)
        date_diff = mood_created.date() - latest_mood_submitted.created.date()
        if date_diff.days == 0:
            return make_response(jsonify({"message": "Mood rating was already submitted today"}), 400)
        elif self.streak >= 1 and date_diff.days == 1:
            streak = self.streak + 1
        else:
            streak = 1

        new_mood = Moods(rating=data['rating'], created=mood_created, user_id=self.id)
        db.session.add(new_mood)
        db.session.commit()
        self.streak = streak
        db.session.commit()
        return make_response(jsonify({"message": "Mood rating submitted"}), 201)

api.add_resource(User, '/user')
api.add_resource(Login, '/login')
api.add_resource(Mood, '/mood')

if __name__ == "__main__":
    app.run(port=8000, debug=True)
