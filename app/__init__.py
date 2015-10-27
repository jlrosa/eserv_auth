from flask import Flask, jsonify, abort, request, make_response, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from flasgger import Swagger

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
Swagger(app)

from app import models


@app.route('/auth/api/users', methods=['GET'])
def get_users():
    """
        Lists the users
        ---
        tags:
          - users

        responses:
          201:
            description: Users listed
        """
    users = models.User.query.all()
    users_json = []
    for u in users:
        user = {
            'id': u.id,
            'username': u.username,
            'firstname': u.firstname,
            'lastname': u.lastname,
            'email': u.email
        }
        users_json.append(user)
    return jsonify({'users': users_json}), 201


@app.route('/auth/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """
        Lists a specific user
        ---
        tags:
          - users

        responses:
          201:
            description: User listed
        """
    u = models.User.query.get(user_id)
    user = {
        'id': u.id,
        'username': u.username,
        'firstname': u.firstname,
        'lastname': u.lastname,
        'email': u.email
    }
    if len(user) == 0:
        abort(404)
    return jsonify({'user': user}), 201


@app.route('/auth/api/users', methods=['POST'])
def create_user():
    """
        Creates a user
        ---
        tags:
          - users

        responses:
          201:
            description: User created
        """
    if not request.json or not 'username' in request.json or not 'hashedPW' in request.json \
            or not 'firstname' in request.json or not 'lastname' in request.json or not 'email' in request.json:
        abort(400)

    user = models.User(username=request.json['username'], hashedPW=request.json['hashedPW'], \
                       firstname=request.json['firstname'], lastname=request.json['lastname'],
                       email=request.json['email'])
    db.session.add(user)
    db.session.commit()

    users = models.User.query.all()
    inserted = models.User.query.get(len(users))
    user_json = {
        'id': inserted.id,
        'username': inserted.username,
        'hashedPW': inserted.hashedPW,
        'first name': inserted.firstname,
        'last name': inserted.lastname,
        'email': inserted.email
    }

    return jsonify({'user': user_json}), 201


@app.route('/auth/api/users/login')
def login():
    """
        Shows the Login webpage
        ---
        tags:
          - users, login
        """
    return render_template('login.html')


@app.route('/auth/api/users/login/tryLogin', methods=['POST'])
def tryLogin():
    """
        Querys the database to check if the credentials are authorized
        ---
        tags:
          - users, login

        responses:
          202:
            description: Login accepted
          401:
            description: Login denied
          400:
            description: Bad request
        """
    if not request.json or not 'username' in request.json or not 'hashedPW' in request.json:
        abort(400)

    login = False
    username = request.json['username']
    hashedPW = request.json['hashedPW']

    users = models.User.query.all()
    for u in users:
        if u.username == username and u.hashedPW == hashedPW:
            login = True
            return jsonify({'login': login}), 202

    return jsonify({'login': login}), 401


@app.route('/auth/api/users/login/addToDB', methods=['POST'])
def addToDB():
    """
        Adds a new social network login to the database
        ---
        tags:
          - users

        responses:
          200:
            description: Already exists
          201:
            description: User created
          400:
            description: Bad request
        """
    if not request.json or not 'network' in request.json or not 'token' in request.json:
        abort(400)

    exists = False
    network = request.json['network']
    tkn = request.json['token']

    if network == "facebook":
        users = models.Facebook.query.all()
    elif network == "twitter":
        if not request.json or not 'secret' in request.json:
            abort(400)
        scrt = request.json['secret']
        users = models.Twitter.query.all()
    elif network == "google":
        users = models.Google.query.all()
    else:
        abort(400)

    for u in users:
        if u.token == tkn:
            exists = True
            return jsonify({'exists': exists}), 200

    if network == "facebook":
        user = models.Facebook(token=tkn)
    elif network == "twitter":
        user = models.Twitter(token=tkn, secret=scrt)
    elif network == "google":
        user = models.Google(token=tkn)

    db.session.add(user)
    db.session.commit()
    return jsonify({'user': True}), 201


@app.route('/auth/api/users/login/facebook')
def loginFb():
    """
        Shows the Login to facebook webpage
        ---
        tags:
          - users, login
        """
    return render_template('facebook.html')


@app.route('/auth/api/users/login/twitter')
def loginTw():
    """
        Shows the Login to twitter webpage
        ---
        tags:
          - users, login
        """
    return render_template('twitter.html')


@app.route('/auth/api/users/login/google')
def loginGg():
    """
        Shows the Login to google webpage
        ---
        tags:
          - users, login
        """
    return render_template('google.html')


@app.route('/auth/api/users/register')
def register():
    """
        Shows the register webpage
        ---
        tags:
          - users, login
        """
    return render_template('register.html')


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
