from app import app
from app.models import Device
from flask import render_template
from datetime import datetime, timedelta

@app.route('/')
@app.route('/index')
def index():
	
	
	known_devices = Device.query.all()
	connected = []
	unconnected = []
	now = datetime.now()
	for d in known_devices:
		if (now-d.last_seen)/timedelta(minutes=1) > 20:
			unconnected.append(d)
		else: connected.append(d)
	
	
	return render_template('index.html',title='NetScan', connected=connected, unconnected=unconnected)

@app.route('/devices')
def devices():

	return 'Devices'
