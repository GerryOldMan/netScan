import re
import subprocess
import sqlite3
from datetime import datetime
import time

#Imports needed for nmapScan and reading xml file:
import xml.etree.ElementTree as ET
import subprocess

def nmapScan(ip):
	
	#Run the nmap scan:
	subprocess.run(['nmap','-sV','-Pn','-O','-oX',ip+'.xml', ip])

	#Set variables for reading nmap xml file:
	tree = ET.parse(ip+'.xml')
	root = tree.getroot()

	#Most of the info found in host tag. Only scanning one host at a time so will be first host tag
	host = root.find('host')
	hostname = None
	vendor = None
	system = 'Unknown'
	#Find the vendor
	#Vendor found in second address tag
	#element.attrib returns a dictionary
	if host is None:
		return 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown'

	
	try:
		address = host.findall('address')
	except:
		address = None
	if address is not None:
		if 'vendor' in address[1].attrib:
			vendor = address[1].attrib['vendor']
	else:
		vendor = 'Unknown'

	#Find the open ports
	#There may be more than one port open.
	#There is one element ports which has chlidren port. There may be an easier way to find this
	try:	
		ports = host.find('ports')
		port = ports.findall('port')
		openPorts = []
		for i in port:
			if 'portid' in i.attrib:
				openPorts.append(i.attrib['portid'])

			services = i.findall('service')
			
	except:
		openPorts = []

	hostname = host.find('hostnames')
	hostname = hostname.find('hostname')
	hostname = hostname.attrib['name']

	#OS is in the OS tag.
	try:
		os = host.find('os')
		
		osmatch = os.findall('osmatch')
		
		if len(osmatch) > 0:
			'''system = osmatch[0].attrib['name']'''
			system = osmatch[0].find('osclass')
			
			try:
				system = system.attrib['osfamily'] + ' ' + system.attrib['osgen']
			except:
				system = 'Unknown'

		#Lastboot might be interesting
		uptime = host.find('uptime')
		if uptime is not None:
			lastboot = uptime.attrib['lastboot']
		else: lastboot = 'Unknown'
	except:
		system = 'Unknown'
		lastboot = 'Unknown'



	print('[+] MAC Vendor: %s Open Ports: %s Hostname: %s' %(vendor, openPorts, hostname))
	return system, vendor, openPorts, hostname, lastboot

#Could download oui file to map against manufacturer.
#Can we link to openvas for vuln scan? Would this negate the need to do a nmap scan?
#Regex to find the ip addresses
ip = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
                +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')


#Possibly put this in a loop to run continuosly?
while True:
	ip = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
                +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')

	#Connect to the database
	db = sqlite3.connect('app.db')
	db.row_factory = sqlite3.Row #This will then return db search as dictionary

	cursor = db.cursor()

	#Run the arp scan to find the connected devices
	connected_devices = subprocess.run(['arp-scan','--interface=eth0','--localnet'], stdout=subprocess.PIPE).stdout.decode('utf-8')
	print('[+] Scan complete')
	print('[+] %s' %connected_devices[connected_devices.find('hosts/sec). ')+12:-1])
	print('[+] Connecting to database')
	known_devices = cursor.execute("""SELECT * FROM device""").fetchall()
	if len(known_devices) > 0:
		print('[+] Found %s known devices in database' %len(known_devices))
	else:
		print('[!] No known devices found!')

	#Now need to search the database to see if any of these devices are in the database or not.
	#Search using the MAC address not the IP address.
	toScan = []
	for device in ip.finditer(connected_devices):
		
		#Search the database for that device
		mac = connected_devices[device.end()+1:device.end()+18]
		ip = device.group(0)
		
		if next((item for item in known_devices if item['mac'] == mac),False) == False:
			print("[*] Unkown Device MAC: %s IP: %s" %(mac,ip))
			#Add a list of ip's to be scanned:
			toScan.append({'ip':ip,'mac':mac})
			#Need to add to database
			first_seen = datetime.now()
			cursor.execute("""INSERT INTO device(mac, ip, first_seen, last_seen) VALUES(?,?,?,?)""", (mac,ip,first_seen,first_seen))
			db.commit()
		else:
			#Need to update last seen time.
			print('[*] Updating device %s' %mac)
			cursor.execute("""UPDATE device SET last_seen = ? WHERE mac = ?""", (datetime.now(), mac))
			toScan.append({'ip':ip,'mac':mac})
			db.commit()
		
	
		

	#db.close()
	#Nmap the to scan list:
	print('[+] Prepearing to nmap scan %s devices' %len(toScan))
	for i in toScan:
		print('[+] Running nmap scan on %s' %i['mac'])
		system, vendor, openPorts, hostname, lastboot = nmapScan(i['ip'])
		cursor.execute("""UPDATE device SET os = ?, vendor = ?, ports = ?, hostname = ?, lastboot = ? WHERE mac = ?""", (system, vendor, str(openPorts), hostname, lastboot, i['mac']))
		db.commit()
	
	#db.commit()
	db.close()	
	
	print('[+] Sleeping')
	time.sleep(180)


