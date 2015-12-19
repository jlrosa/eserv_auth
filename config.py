from authomatic.providers import oauth2, oauth1

import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

CONFIG = {
    'google': {
        'class_': oauth2.Google,
        'id': 3,
        'consumer_key': 'CONSUMER_KEY',
        'consumer_secret': 'CONSUMER_SECRET',
        'scope': oauth2.Google.user_info_scope,
    },
}
