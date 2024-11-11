from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, get_jwt, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import json
from dotenv import load_dotenv
import os
from flask_cors import CORS
from datetime import timedelta
# from hmac import compare_digest

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])
load_dotenv()


# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)


jwt = JWTManager(app)
db = SQLAlchemy(app)
blocklist = set()


# Creating out my models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.id, self.username, self.email, self.password}>'


@app.route("/")
def index():
    return "Hello world", 200


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Extract fields
    email = data.get('email')
    password = data.get('password')

    # Find user by username
    user = User.query.filter_by(email=email).first()

    # Check if user exists and if the password is correct
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    # Create JWT access token
    access_token = create_access_token(identity=user.email)
    return jsonify(access_token=access_token), 200


# This routes creates a routes for registration of users
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Extract fields
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check if the username or email already exists
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 409

    # Hash the password and create the new user
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    new_user = User(username=username, email=email, password=hashed_password)

    # Add to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blocklist

# # Register a callback function that takes whatever object is passed in as the
# # identity when creating JWTs and converts it to a JSON serializable format.
# @jwt.user_identity_loader
# def user_identity_lookup(user):
#     return user.id


# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(email=identity).one_or_none()

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # Get the unique identifier of the JWT
    blocklist.add(jti)      # Add the jti to the blocklist
    return jsonify({"message": "Successfully logged out"}), 200




@app.route("/user", methods=["GET"])
@jwt_required()
def user():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
    )


# @app.route("/my_name")
# # @jwt_required()
# def name():
#     return "my name is Chijiuba Onyedikachukwu", 200


# if __name__ == "__main__":
#     app.run(debug=True)

