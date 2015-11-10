from flask import Flask, flash, jsonify, abort, request, redirect, make_response, render_template, session, url_for
from flask_oauth import OAuth
from flask.ext.sqlalchemy import SQLAlchemy
from authomatic.adapters import WerkzeugAdapter
from authomatic import Authomatic
from authomatic.providers import oauth2
from flasgger import Swagger
from rauth.service import OAuth1Service
from rauth.utils import parse_utf8_qsl

# Documentation URL: http://localhost:5000/apidocs/index.html

FACEBOOK_APP_ID = '1645713445676362'
FACEBOOK_APP_SECRET = 'c7a14d197e7491236102b9f1f8dba1e9'
TW_KEY = "AAAMLSOPNuRwiWP1C2ccIHTKn"
TW_SECRET = "63qLnliFUdQtmITYvB3G8sN8g1xlzLFplOzdfL1uablGATgMZj"
CONFIG = {
    'google': {
        'class_': oauth2.Google,
        'consumer_key': '1023452814056-s6c5f9mbco09cdjbipi9lh8p707g08jh.apps.googleusercontent.com',
        'consumer_secret': '6yzy1n9w_RVSchWYHhC7p-xI',
        'scope': oauth2.Google.user_info_scope,
    },
}

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
            'name': u.name,
            'email': u.email
        }
        users_json.append(user)
    return jsonify({'users': users_json}), 201


@app.route('/auth/api/users/<int:regID>', methods=['GET'])
def get_user(regID):
    """
        Lists a specific user
        ---
        tags:
          - users

        responses:
          201:
            description: User listed
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
    return jsonify({'user': user}), 201


@app.route('/auth/api/users/login')
def login():
    """
        Shows the Login webpage
        ---
        tags:
          - users, login
        """
    username = session.get('username', None)
    if username is None:
        username = 'a'
    network = session.get('network', None)
    if network is None:
        network = 'a'
    user = {'name': username, 'socialnetwork': network}
    return render_template('login.html', user=user)


def addToDB(name, id, email, token, network):
    networkid = 0
    users = models.User.query.all()
    for u in users:
        if network == "facebook":
            networkid = u.fbid
        elif network == "twitter":
            networkid = u.twid
        elif network == "google":
            networkid = u.ggid

        if u.email == email and int(networkid) == int(id):
            print("found user")
            if u.token == token:
                print("same token")
                return 'Exists', u
            else:
                print("different token")
                u.token = token
                db.session.commit()
                return 'Updated', u

    if network == "facebook":
        newUser = models.User(name=name, email=email, token=token, fbid=id)
    elif network == "twitter":
        newUser = models.User(name=name, email=email, token=token, twid=id)
    elif network == "google":
        newUser = models.User(name=name, email=email, token=token, ggid=id)

    db.session.add(newUser)
    db.session.commit()
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
    session['username'] = name
    session['network'] = 'facebook'
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
                      params={'format': 'json'}).json()

    name = verify['name']
    id = verify['id']
    token = sess.access_token
    secret = sess.access_token_secret
    #print(verify['email'])
    addToDB(name, id, '', token, 'twitter')
    session['username'] = verify['name']
    session['network'] = 'twitter'
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
        session['username'] = result.user.name
        session['network'] = 'google'
        return redirect(url_for('login'))

    return response


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
