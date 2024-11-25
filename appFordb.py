"""
Rename this file to app.py
to use database as storage after
setting up your db credentials
"""

import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from models import db, User, BlacklistedToken
import jwt
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

""" 
#Comment out if need to use database storage
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)
"""

def create_token(user_id, token_type='access'):
    payload = {
        'user_id': user_id,
        'type': token_type,
        'exp': datetime.utcnow() + (
            app.config['JWT_REFRESH_TOKEN_EXPIRES']
            if token_type == 'refresh'
            else app.config['JWT_ACCESS_TOKEN_EXPIRES']
        )
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        token = token.split(' ')[1] if len(token.split(' ')) > 1 else token
        
        try:
            if BlacklistedToken.query.filter_by(token=token).first():
                return jsonify({'error': 'Token has been revoked'}), 401
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if data['type'] != 'access':
                return jsonify({'error': 'Invalid token type'}), 401
            
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
        
    hashed_password = bcrypt.hashpw(
        data['password'].encode('utf-8'),
        bcrypt.gensalt()
    )
    
    new_user = User(
        email=data['email'],
        password=hashed_password.decode('utf-8')
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
        
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not bcrypt.checkpw(
        data['password'].encode('utf-8'),
        user.password.encode('utf-8')
    ):
        return jsonify({'error': 'Invalid credentials'}), 401
        
    access_token = create_token(user.id, 'access')
    refresh_token = create_token(user.id, 'refresh')
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200

@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({
        'message': f'Hello {current_user.email}! This is a protected endpoint.'
    }), 200

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization').split(' ')[1]
    blacklisted_token = BlacklistedToken(token=token)
    db.session.add(blacklisted_token)
    db.session.commit()
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/refresh', methods=['POST'])
def refresh():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'error': 'Token is missing'}), 401
        
    token = token.split(' ')[1] if len(token.split(' ')) > 1 else token
    
    try:
        if BlacklistedToken.query.filter_by(token=token).first():
            return jsonify({'error': 'Token has been revoked'}), 401
            
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        if data['type'] != 'refresh':
            return jsonify({'error': 'Invalid token type'}), 401
            
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 401
            
        new_access_token = create_token(user.id, 'access')
        return jsonify({'access_token': new_access_token}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
