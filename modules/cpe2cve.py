# Adapted from Author: Matteo (xonoxitron) Pisani
# Description: Given a CPE, this script returns all related CVE, ordered by severity (desc)
# Usage: python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54

# Import necessary modules
import argparse
import requests


# Function to retrieve CVE data for a given CPE
def get_cve_data(cpe):
    print("[~] Current CPE > " +cpe)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query_params = {"cpeName": cpe}
    response = requests.get(base_url, params=query_params)
    #print(response.status_code)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data.get("vulnerabilities", [])
    else:
        print(f"[X] Cannot match any CVE for CPE")
        return None



def search(cpe_list):
    # Retrieve CVE data for the given CPE
    cve_list = []
    for cpe in cpe_list:
        cve_data = get_cve_data(cpe)

        if cve_data == None:
            continue

        unsorted_cve=[]
        for i in range (len(cve_data)):
            auxlist=[]
            auxlist.append(cve_data[i].get("cve").get("id"))
            if (cve_data[i].get("cve").get("metrics").get("cvssMetricV31") != None) : 
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV31")[0].get("cvssData").get("baseScore"))
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV31")[0].get("cvssData").get("baseSeverity"))
            elif (cve_data[i].get("cve").get("metrics").get("cvssMetricV30") != None) : 
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV30")[0].get("cvssData").get("baseScore"))
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV30")[0].get("cvssData").get("baseSeverity"))
            elif (cve_data[i].get("cve").get("metrics").get("cvssMetricV2") != None) : 
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV2")[0].get("impactScore"))
                auxlist.append(cve_data[i].get("cve").get("metrics").get("cvssMetricV2")[0].get("baseSeverity"))
            unsorted_cve.append(auxlist)


        unsorted_cve.sort(key=lambda x: x[1])
        sorted_cve=unsorted_cve[::-1]
        cve_list.append(sorted_cve)
    return(cve_list)
