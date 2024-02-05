# Adapted from Author: Matteo (xonoxitron) Pisani
# Description: Given a CPE, this script returns all related CVE, ordered by severity (desc)
# Usage: python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54

# Import necessary modules
import argparse
import requests


# Function to retrieve CVE data for a given CPE
def get_cve_data(cpe):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query_params = {"cpeName": cpe}
    response = requests.get(base_url, params=query_params)
    #print(response.status_code)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data.get("vulnerabilities", [])
    else:
        print(f"Error in HTTP request: {response.status_code}")
        return []


# Main function for parsing command-line arguments and performing the sorting and printing
def search(cpe):
    # Set up the argument parser
    #parser = argparse.ArgumentParser(description="Get and sort CVEs from a CPE")
    #parser.add_argument(
    #    "-c", "--cpe", required=True, help="CPE from which to retrieve CVEs"
    #)
    #args = parser.parse_args()

    # Retrieve CVE data for the given CPE
    cve_data = get_cve_data(cpe)
    #print(cve_data)
    # Sort the CVEs by score in descending order
    #sorted_cve = sorted(cve_data["CVE_Items"], key=get_cve_score, reverse=True)
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
    #print(unsorted_cve)

    
    # Print the sorted CVEs
    unsorted_cve.sort(key=lambda x: x[1])
    sorted_cve=unsorted_cve[::-1]
    return(sorted_cve)


print(search('cpe:2.3:a:apache:http_server:2.4.57'))