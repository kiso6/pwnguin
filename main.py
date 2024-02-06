import modules.nmdiscovery as nm
import modules.cpe2cve as cpe2cve
import modules.cve2exploit as cve2exp
import subprocess
import time
from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.msfrpc import MsfRpcClient
import pprint as pp

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


def show_pwnguin():
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


def main():
    show_pwnguin()
    SCAN = nm.scan_target("192.168.239.250")

    extracted = nm.extraction(SCAN)
    print("[V] Nmap scan found protocols :")
    print(nm.extract_protocol(extracted))
    print("\n")

    print("Extracting CPEs...")
    CPE = nm.extract_cpe(extracted)
    if CPE:
        print("[V] CPE List based on nmap scan :")
        pp.pprint(CPE)
        print("\n")
    else:
        print("[X] No CPE found or Error in nmap scan.")
        return -5

    print("Searching for CVEs based on CPEs...")
    CVE_0 = cpe2cve.search(CPE)

    if CVE_0:
        CVE = []
        print("\n[V] CVE List based on NVD NIST database :")
        for cpe, cves in CVE_0.items():
            print(cpe)
            if not cves:
                print(" - no cve found")
            for cve in cves:
                CVE.append(cve[0])
                print(f" - {cve[0]:<14} {cve[1]:<4} {SEVERITY_TEXT[cve[2]]}")

        print("")
    else:
        print("[X] Error in database search.")
        return -10

    if CVE:
        print("Starting msfrpcd...")
        proc = subprocess.run("msfrpcd -P yourpassword", shell=True)
        time.sleep(5)

        if proc:
            client = MsfRpcClient("yourpassword", ssl=True)

        print("[V] Metasploit Exploits list :\n")
        EXPLOIT = cve2exp.getexploit(CVE, client)
        print("\n")
        subprocess.run("kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True)
    else:
        print("[X] Error in exploit search.\n")
        return -70


if __name__ == "__main__":
    main()
