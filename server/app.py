from flask import Flask, request, jsonify, session
from flask_migrate import Migrate
from flask_restful import Resource, Api
from server.extensions import db, bcrypt


from server.models import User, Recipe

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'

db.init_app(app)
bcrypt.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

# Routes

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    try:
        new_user = User(
            username=data['username'],
            image_url=data.get('image_url'),
            bio=data.get('bio')
        )
        new_user.password_hash = data['password']
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id

        return {
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }, 201
    except:
        return {'error': 'Unprocessable Entity'}, 422

@app.route('/check_session')
def check_session():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
    return {}, 401

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user and user.authenticate(data.get('password')):
        session['user_id'] = user.id
        return {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }, 200

    return {'error': 'Invalid username or password'}, 401

@app.route('/logout', methods=['DELETE'])
def logout():
    if session.get('user_id'):
        session.pop('user_id')
        return {}, 204
    return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [{
            'id': r.id,
            'title': r.title,
            'instructions': r.instructions,
            'minutes_to_complete': r.minutes_to_complete,
            'user': {
                'id': r.user.id,
                'username': r.user.username,
                'image_url': r.user.image_url,
                'bio': r.user.bio
            }
        } for r in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()
        if len(data.get('instructions', '')) < 50:
            return {'error': 'Instructions must be at least 50 characters long'}, 422

        recipe = Recipe(
            title=data['title'],
            instructions=data['instructions'],
            minutes_to_complete=data['minutes_to_complete'],
            user_id=user_id
        )

        db.session.add(recipe)
        db.session.commit()

        return {
            'id': recipe.id,
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user': {
                'id': recipe.user.id,
                'username': recipe.user.username,
                'image_url': recipe.user.image_url,
                'bio': recipe.user.bio
            }
        }, 201

api.add_resource(RecipeIndex, '/recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
