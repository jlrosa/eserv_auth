from authomatic import Authomatic
from authomatic.adapters import WerkzeugAdapter
from config import CONFIG
from flasgger import Swagger
from flask import Flask, flash, jsonify, abort, request, redirect, make_response, render_template, session, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask_oauth import OAuth
from rauth.service import OAuth1Service
from rauth.utils import parse_utf8_qsl

# Documentation URL: http://localhost:5000/apidocs/index.html

FACEBOOK_APP_ID = '1645713445676362'
FACEBOOK_APP_SECRET = 'c7a14d197e7491236102b9f1f8dba1e9'
TW_KEY = "w1gNY1jr4JR8tCg5Gm0Fxc3sr"
TW_SECRET = "cMDqfKoA7CVdVQk3AXlKT7bQjakwQ2vXIqrv0LdEczWY9eio7k"


app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
Swagger(app)
app.secret_key = '\xfb\x12\xdf\xa1@i\xd6>V\xc0\xbb\x8fp\x16#Z\x0b\x81\xeb\x16'
authomatic = Authomatic(CONFIG, app.secret_key)
oauth = OAuth()

from app import models

facebook = oauth.remote_app('facebook',
                            base_url='https://graph.facebook.com/',
                            request_token_url=None,
                            access_token_url='/oauth/access_token',
                            authorize_url='https://www.facebook.com/dialog/oauth',
                            consumer_key=FACEBOOK_APP_ID,
                            consumer_secret=FACEBOOK_APP_SECRET,
                            request_token_params={'scope': 'email'}
                            )

twitter = OAuth1Service(
    name='twitter',
    consumer_key=TW_KEY,
    consumer_secret=TW_SECRET,
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    base_url='https://api.twitter.com/1.1/')


@app.route('/auth/api/users/setRegID', methods=['POST'])
def set_regID():
    """
    Sets the regID for the user with the given ID
    ---
    tags:
      - users
      - regID
    parameters:
      - name: id
        in: body
        type: int
        description: id of the user
      - name: regID
        in: body
        type: int
        description: regID to be set
    responses:
      200:
        description: The user was updated
        schema:
          user: status
      400:
        description: Request malformed
      401:
        description: The user doesn't exist
        schema:
          user: status
    """
    if not request.json or not 'regID' in request.json or not 'id' in request.json:
        abort(400)

    regID = request.json.get('regID', "")
    id = request.json['id']

    user = models.User.query.get(id)
    if user:
        user.regid = str(regID)
        db.session.commit()
        return jsonify({'user': 'updated'}), 200

    return jsonify({'user': 'not found'}), 401


@app.route('/auth/api/users', methods=['GET'])
def get_users():
    """
    Lists all the users in the database. #It's only a test service, should not be used#
    ---
    tags:
      - users
    responses:
      200:
        description: The list of users
    """
    users = models.User.query.all()
    users_json = []
    for u in users:
        user = {
            'id': u.id,
            'name': u.name,
            'email': u.email
        }
        users_json.append(user)
    return jsonify({'users': users_json}), 200


'''@app.route('/auth/api/users/<int:regID>', methods=['GET'])
def get_user_by_regid(regID):
    """
    Gives the information of an user based on his regID
    ---
    tags:
      - users
      - regID
    parameters:
      - name: regID
        in: path
        type: integer
        description: the regID to be searched
    responses:
      200:
        description: The user with the given regID
        schema:
          properties:
            result:
              type: user
              description: The user
    """
    users = models.User.query.all()
    for u in users:
        if regID == u.regID:
            user = {
                'id': u.id,
                'name': u.name,
                'email': u.email
            }

    if len(user) == 0:
        abort(404)
    return jsonify({'user': user}), 200'''


@app.route('/auth/api/users/<int:id>', methods=['GET'])
def get_user_by_id(id):
    """
    Gives the information of an user based on his id
    ---
    tags:
      - users
    parameters:
      - name: ID
        in: path
        type: integer
        description: the ID to be searched
    responses:
      200:
        description: The user with the given ID
        schema:
          properties:
            result:
              type: user
              description: The user
      404:
        description: User not found
    """
    users = models.User.query.all()
    for u in users:
        if id == u.id:
            user = {
                'id': u.id,
                'name': u.name,
                'email': u.email,
                'regID': u.regid
            }

    if len(user) == 0:
        abort(404)
    return jsonify({'user': user}), 201


@app.route('/auth/api/users/login')
def login():
    id = session.get('user', None)
    print(id)
    if id is not None:
        user = models.User.query.get(id)
        print(user)
        if user:
            fb = False
            tw = False
            gg = False
            if int(user.fbid) != 0:
                fb = True
            if int(user.twid) != 0:
                tw = True
            if int(user.ggid) != 0:
                gg = True

            user = {'name': user.name, 'id': id,'fb': fb, 'tw': tw, 'gg': gg}
            print(user)
            return render_template('login.html', user=user)

    user = {'name': '', 'id': 0, 'fb': False, 'tw': False, 'gg': False}
    return render_template('login.html', user=user)


'''@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login/<provider_name>/', methods=['GET'])
def loginNetwork(provider_name):
    # We need response object for the WerkzeugAdapter.
    response = make_response()

    # Log the user in, pass it the adapter and the provider name.
    result = authomatic.login(
        WerkzeugAdapter(request, response),
        provider_name,
        session=session,
        session_saver=lambda: app.save_session(session, response)
    )

    # If there is no LoginResult object, the login procedure is still pending.
    if result:
        if result.user:
            # We need to update the user to get more info.
            result.user.update()
            print(result.user)
            print(result.user.data)
            print(result.user.content)
            print(result.user.provider)
            print(result.user.picture)
            print(result.user.credentials)

        # The rest happens inside the template.
        return render_template('login_temp.html', result=result)

    # Don't forget to return the response.
    return response'''


def addToDB(name, id, email, token, network):
    networkid = 0
    fbid = 0
    twid = 0
    ggid = 0

    prev_id = session.get('user', None)
    print(prev_id)
    if prev_id is not None:
        user = models.User.query.get(prev_id)
        print(user)
        if user:
            if int(user.fbid) != 0:
                fbid = user.id
            if int(user.twid) != 0:
                twid = user.id
            if int(user.ggid) != 0:
                ggid = user.id

    users = models.User.query.all()
    for u in users:
        if network == "facebook":
            networkid = u.fbid
            fbid = networkid
        elif network == "twitter":
            networkid = u.twid
            twid = networkid
        elif network == "google":
            networkid = u.ggid
            ggid = networkid

        if str(u.email) == str(email) and int(networkid) == int(id):
            if u.token == token:
                print("same token")
                if network == "facebook":
                    u.twid = twid
                    u.ggid = ggid
                elif network == "twitter":
                    u.fbid = fbid
                    u.ggid = ggid
                elif network == "google":
                    u.fbid = fbid
                    u.twid = twid
                db.session.commit()
                session['user'] = u.id
                return 'Exists', u
            else:
                print("diff token")
                if network == "facebook":
                    print("facebook")
                    u.twid = twid
                    u.ggid = ggid
                elif network == "twitter":
                    print("twitter")
                    u.fbid = fbid
                    u.ggid = ggid
                elif network == "google":
                    print("google")
                    u.fbid = fbid
                    u.twid = twid
                u.token = token
                db.session.commit()
                session['user'] = u.id
                return 'Updated', u

    if network == "facebook":
        newUser = models.User(name=name, email=email, token=token, fbid=id, twid=twid, ggid=ggid)
    elif network == "twitter":
        newUser = models.User(name=name, email=email, token=token, fbid=fbid, twid=id, ggid=ggid)
    elif network == "google":
        newUser = models.User(name=name, email=email, token=token, fbid=fbid, twid=twid, ggid=id)

    db.session.add(newUser)
    db.session.commit()
    users = models.User.query.all()
    id = users[-1].id
    session['user'] = id
    return 'Created', newUser


@app.route('/auth/api/users/login/facebook')
def loginFb():
    return facebook.authorize(callback=url_for('facebook_authorized',
                                               next=request.args.get('next') or request.referrer or None,
                                               _external=True))


@app.route('/auth/api/users/login/facebook/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('me?fields=id,name,email')
    id = me.data['id']
    token = resp['access_token']
    name = me.data['name']
    email = me.data['email']
    addToDB(name, id, email, token, 'facebook')
    return redirect(url_for('login'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


@app.route('/auth/api/users/login/twitter')
def loginTw():
    oauth_callback = url_for('authorized', _external=True)
    params = {'oauth_callback': oauth_callback}

    r = twitter.get_raw_request_token(params=params)
    data = parse_utf8_qsl(r.content)

    session['twitter_oauth'] = (data['oauth_token'],
                                data['oauth_token_secret'])
    return redirect(twitter.get_authorize_url(data['oauth_token'], **params))


@app.route('/auth/api/users/login/twitter/authorized')
def authorized():
    request_token, request_token_secret = session.pop('twitter_oauth')

    # check to make sure the user authorized the request
    if not 'oauth_token' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))

    try:
        creds = {'request_token': request_token,
                 'request_token_secret': request_token_secret}
        params = {'oauth_verifier': request.args['oauth_verifier']}
        sess = twitter.get_auth_session(params=params, **creds)
    except Exception, e:
        flash('There was a problem logging into Twitter: ' + str(e))
        return redirect(url_for('not_found'))

    verify = sess.get('account/verify_credentials.json',
                      params={'format': 'json', 'include_email': 'true'}).json()

    name = verify['name']
    id = verify['id']
    email = verify['email']
    token = sess.access_token
    secret = sess.access_token_secret
    addToDB(name, id, email, token, 'twitter')
    return redirect(url_for('login'))


@app.route('/auth/api/users/login/google')
def loginGg(provider_name="google"):
    response = make_response()

    # Authenticate the user
    result = authomatic.login(WerkzeugAdapter(request, response), provider_name)

    if result:
        if result.user:
            # Get user info
            result.user.update()

        name = result.user.name
        id = result.user.id
        email = result.user.email
        token = result.user.credentials.token
        addToDB(name, id, email, token, 'google')
        return redirect(url_for('login'))

    return response


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
