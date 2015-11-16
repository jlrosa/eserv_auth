from authomatic.providers import oauth2, oauth1, openid

import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

CONFIG = {
    'facebook': {
        'class_': oauth2.Facebook,
        'id': 1,
        'consumer_key': '1645713445676362',
        'consumer_secret': 'c7a14d197e7491236102b9f1f8dba1e9',
        'scope': ['public_profile', 'user_about_me', 'email'],
    },

    'twitter': {
        'class_': oauth1.Twitter,
        'id': 2,
        'consumer_key': 'AAAMLSOPNuRwiWP1C2ccIHTKn',
        'consumer_secret': '63qLnliFUdQtmITYvB3G8sN8g1xlzLFplOzdfL1uablGATgMZj',
    },

    'google': {
        'class_': oauth2.Google,
        'id': 3,
        'consumer_key': '1023452814056-s6c5f9mbco09cdjbipi9lh8p707g08jh.apps.googleusercontent.com',
        'consumer_secret': '6yzy1n9w_RVSchWYHhC7p-xI',
        'scope': oauth2.Google.user_info_scope,
    },
}