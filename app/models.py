from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), index=True)
    token = db.Column(db.Text, index=True, unique=True)
    regid = db.Column(db.Text, default=0)
    fbid = db.Column(db.String(100), index=True, default=0)
    twid = db.Column(db.String(100), index=True, default=0)
    ggid = db.Column(db.String(100), index=True, default=0)
    photo = db.Column(db.Text)
    isFb = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r' % self.name
