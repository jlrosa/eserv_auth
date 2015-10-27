from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
facebook = Table('facebook', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('token', Text),
    Column('user_id', Integer),
)

google = Table('google', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('token', Text),
    Column('user_id', Integer),
)

twitter = Table('twitter', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('token', Text),
    Column('user_id', Integer),
)

user = Table('user', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('username', String(length=50)),
    Column('hashedPW', Text),
    Column('firstname', String(length=50)),
    Column('lastname', String(length=50)),
    Column('email', String(length=50)),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['facebook'].create()
    post_meta.tables['google'].create()
    post_meta.tables['twitter'].create()
    post_meta.tables['user'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['facebook'].drop()
    post_meta.tables['google'].drop()
    post_meta.tables['twitter'].drop()
    post_meta.tables['user'].drop()
