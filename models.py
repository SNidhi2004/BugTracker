from flask_login import UserMixin
from db import mongo
from flask_bcrypt import generate_password_hash, check_password_hash

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.name = user_doc['name']
        self.email = user_doc['email']
        self.role = user_doc.get('role', 'Developer')

    @staticmethod
    def find_by_email(email):
        user = mongo.db.users.find_one({'email': email})
        return User(user) if user else None

    @staticmethod
    def create(name, email, password, role='Developer'):
        pw_hash = generate_password_hash(password).decode('utf-8')
        user_id = mongo.db.users.insert_one({'name': name, 'email': email, 'password': pw_hash, 'role': role}).inserted_id
        user = mongo.db.users.find_one({'_id': user_id})
        return User(user)

    def check_password(self, password):
        user = mongo.db.users.find_one({'_id': mongo.db.ObjectId(self.id)})
        return check_password_hash(user['password'], password)
