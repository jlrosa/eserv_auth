from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), index=True)
    token = db.Column(db.Text, index=True, unique=True)
    regid = db.Column(db.Text, index=True, unique=True)
    fbid = db.Column(db.Integer, index=True, default=0)
    twid = db.Column(db.Integer, index=True, default=0)
    ggid = db.Column(db.Integer, index=True, default=0)
    #facebook_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #twitter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #google_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #facebook = db.relationship('User', backref='id', lazy='dynamic')
    #twitter = db.relationship('User', backref='id', lazy='dynamic')
    #google = db.relationship('User', backref='id', lazy='dynamic')

    def __repr__(self):
        return '<User %r' % self.name