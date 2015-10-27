from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    hashedPW = db.Column(db.Text, index=True, unique=True)
    firstname = db.Column(db.String(50), index=True, unique=True)
    lastname = db.Column(db.String(50), index=True)
    email = db.Column(db.String(50), index=True, unique=True)
    facebook = db.relationship('Facebook', backref='author', lazy='dynamic')
    twitter = db.relationship('Twitter', backref='author', lazy='dynamic')
    google = db.relationship('Google', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User %r' % self.username


class Facebook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Facebook %r>' % self.token


class Twitter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, index=True, unique=True)
    secret = db.Column(db.Text, index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Twitter %r>' % self.token


class Google(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Google %r>' % self.token
