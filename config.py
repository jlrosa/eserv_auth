from authomatic.providers import oauth2, oauth1

import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

CONFIG = {
    'google': {
        'class_': oauth2.Google,
        'id': 3,
        'consumer_key': '1023452814056-s6c5f9mbco09cdjbipi9lh8p707g08jh.apps.googleusercontent.com',
        'consumer_secret': '6yzy1n9w_RVSchWYHhC7p-xI',
        'scope': oauth2.Google.user_info_scope,
    },
}