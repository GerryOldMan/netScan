from app import db

class Device(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	mac = db.Column(db.String(20), index=True, unique=True)
	ip = db.Column(db.String(25), index=True)
	last_seen = db.Column(db.DateTime, index=True)
	first_seen = db.Column(db.DateTime, index=True)
	nampHTML = db.Column(db.String(40), index=True)
	os = db.Column(db.String(100), index=True)
	vendor = db.Column(db.String(50), index=True)
	hostname = db.Column(db.String(100), index=True)
	ports = db.Column(db.String(100), index=True)
	lastboot = db.Column(db.String(50), index=True)

	def __repr__(self):
		return '<DEVICE MAC {}>'.format(self.mac)
