import pandas as pd
import nmap
import math


# https://nmap.org/book/man-briefoptions.html

# Call: IP = str | ports "first-last" | options = string des options nmap


def scan_target(IP="127.0.0.1", ports="1-1023", options="-sV -Pn"):
    """Perform an nmap scan on the given IP with the specified ports and options"""
    scan = nmap.PortScanner()
    scan.scan(IP, ports, arguments=options, sudo=True)
    res = None
    # print(scan.command_line()) ---> debug
    if scan[IP].state() == "up":
        otp = open("./scan.csv", "w+")
        otp.write(scan.csv())
        otp.close()
        res = pd.read_csv("./scan.csv", sep=";")
    else:
        print("Target is down, leaving...\n")
        return -1
    return res


# For general purposes
def extraction(nmap_data):
    """Extract the relevant information from the nmap scan result and return it as a dictionary"""
    extr = {}
    for i in range(len(nmap_data)):
        NAME = nmap_data.iloc[i, 5]
        PORT = nmap_data.iloc[i, 4]
        PRODUCT = nmap_data.iloc[i, 7]
        EXTRAINFO = nmap_data.iloc[i, 8]
        VERSION = nmap_data.iloc[i, 10]
        CPE = nmap_data.iloc[i, 12]
        inpt = {
            "name": NAME,
            "port": PORT,
            "product": PRODUCT,
            "extra": EXTRAINFO,
            "vers": VERSION,
            "cpe": CPE,
        }
        extr[i] = inpt
    return extr


def extract_protocol(extracted):
    """Extract the protocol names from the extracted data"""
    out = []
    for k in range(len(extracted)):
        out.append(extracted[k]["name"])
    return out


# For CVE search with cpe
def extract_cpe(extracted):
    """Extract the CPEs from the extracted data and return them in a list of strings in the format cpe:2.3:a"""
    out = []
    for k in range(len(extracted)):
        if not isinstance(extracted[k]["cpe"], str) and math.isnan(extracted[k]["cpe"]):
            print(f"no CPE found for {extracted[k]['name']}")
            continue
        lol = ""
        lol = extracted[k]["cpe"][0:3] + ":2.3:" + extracted[k]["cpe"][5:]
        if lol not in out:
            out.append(lol)
    return out


# # 4 test only
# import pprint
# obj = extraction(scan_target())
# pprint.pprint(obj,sort_dicts=False)
# print(extract_cpe(obj))
