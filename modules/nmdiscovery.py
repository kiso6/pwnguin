import pandas as pd 
import nmap


# https://nmap.org/book/man-briefoptions.html

# Call: IP = str | ports "first-last" | options = string des options nmap

def scan_target(IP='127.0.0.1',ports='1-1023',options="-sV -Pn"):
    scan = nmap.PortScanner()
    scan.scan(IP,ports,arguments=options,sudo=True)
    res = None
    # print(scan.command_line()) ---> debug
    if scan[IP].state() == 'up':
        otp = open("./scan.csv","w+")
        otp.write(scan.csv())
        otp.close()
        res = pd.read_csv("./scan.csv",sep=";")
    else: 
        print("Target is down, leaving...\n")
        return -1
    return res

# For general purposes
def extraction(resultCSV):
    extr = {}
    for i in range(len(resultCSV)):
        NAME = resultCSV.iloc[i,5]
        PORT = resultCSV.iloc[i,4]
        PRODUCT = resultCSV.iloc[i,7]
        EXTRAINFO = resultCSV.iloc[i,8]
        VERSION = resultCSV.iloc[i,10]
        CPE = resultCSV.iloc[i,12]
        inpt = {"name" : NAME,
                "port" : PORT,
                "product" : PRODUCT,
                "extra" : EXTRAINFO,
                "vers" : VERSION,
                "cpe" : CPE}
        extr[i] = inpt
    return extr

def extract_protocol(diction):
    out = []
    for k in range(len(diction)):
        out.append(diction[k]['name'])
    return out


# For CVE search with cpe
def extract_cpe(diction):
    out = []
    for k in range(len(diction)):
        lol =""
        lol = diction[k]['cpe'][0:3]+":2.3:"+diction[k]['cpe'][5:]
        out.append(lol)
    return out


# 4 test only
import pprint
obj = extraction(scan_target())
pprint.pprint(obj,sort_dicts=False)
print(extract_cpe(obj))
