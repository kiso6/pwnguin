import modules.nmdiscovery as nm
import modules.cpe2cve as c2cve
import modules.cve2exploit as c2exp
import subprocess
import time
from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.msfrpc import MsfRpcClient
import pprint as pp

def pwnguin():
    RED = "\033[1;31m"
    YELLOW = "\033[33m"
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    GREEN = "\033[0;32m"
    RESET = "\033[0;0m"
    BOLD = "\033[;1m"
    REVERSE = "\033[;7m"
    print(f"""
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
            """)


def main():
    pwnguin()
    SCAN = nm.scan_target('127.0.0.1')
    
    CPE = nm.extract_cpe(nm.extraction(SCAN))

    if (CPE):
        print('[V] CPE List based on nmap scan :\n')
        pp.pprint(CPE)
        print("\n")
    else:
        print('[X] Error in nmap scan.\n')
        return(-5)

    CVE_0= c2cve.search(CPE)

    if (CVE_0):
        CVE = []
        for k in range(len(CVE_0)):
            for i in range(len(CVE_0[k])):
                CVE.append(CVE_0[k][i][0])
        print('[V] CVE List based on NVD NIST database :\n')
        pp.pprint(CVE)
        print("\n")
    else:
        print('[X] Error in database search.\n')
        return(-10)


    if (CVE):
        proc = subprocess.run("msfrpcd -P yourpassword",shell=True)
        time.sleep(5)

        if (proc):
            client = MsfRpcClient('yourpassword', ssl=True)

        print('[V] Metasploit Exploits list :\n')
        EXPLOIT = c2exp.getexploit(CVE,client)
        print("\n")
    else:
        print('[X] Error in exploit search.\n')
        return(-70)
    
if __name__ == "__main__":
    main()