import json
import ipaddress


class Computer:

    def __init__(self, is_local=False):
        self.vulnerabilities: list[dict] = []
        self.networks: list[dict] = (
            []
        )  # iface/network couples (network is a computer ip with mask)
        self.is_local = (
            is_local  # Is this computer the computer from which the tests are done
        )
        self.arp: list[dict] = []  # arp table ip/mac/iface triples
        self.os: str = ""
        self.infection: dict = {"infected": False, "via": None}

    def add_network(self, iface: str, network: str):
        self.networks.append({"iface": iface, "network": network})

    def add_arp_entry(self, ip: str, mac: str, iface: str):
        self.arp.append({"IP": ip, "MAC": mac, "iface": iface})

    def set_infection(
        self, infected: bool, via: str | None = None, port: int | None = None
    ):
        self.infection = {"infected": infected, "via": via, "port": port}

    @classmethod
    def fromJSON(cls, json_dict):
        computer = cls()
        computer.vulnerabilities = json_dict["vulnerabilities"]
        computer.networks = [
            {"iface": entry["iface"], "network": entry["network"]}
            for entry in json_dict["networks"]
        ]
        computer.arp = [
            {"IP": entry["IP"], "MAC": entry["MAC"], "iface": entry["iface"]}
            for entry in json_dict["arp"]
        ]
        computer.os = json_dict["os"]
        computer.infection = json_dict["infection"]
        computer.is_local = json_dict["is_local"]
        return computer


def save(computers: dict[str, Computer], file_location: str = "./save.json"):
    save_str = json.dumps(
        computers, default=lambda o: o.__dict__, sort_keys=True, indent=4
    )
    with open(file_location, "w") as f:
        f.write(save_str)


def load(file_location: str = "./save.json") -> dict[str, Computer]:
    data = {}
    try:
        with open(file_location, "r") as f:
            data = json.loads(f.read())
    except Exception as e:
        pass
    return {ip: Computer.fromJSON(computer_json) for ip, computer_json in data.items()}


def computers_to_network(computers: dict[str, Computer]):
    """Convert a dict of ip(with mask)/Computer to a tree of networks/computers"""
    networks = {}
    for ip, computer in computers.items():
        network = str(ipaddress.ip_network(ip, strict=False))
        add_ip_to_network(networks, network, ip.split("/")[0])
        # Add network from others IPs of computer
        for c_network in computer.networks:
            c_ip = c_network["network"].split("/")[0]
            c_network = str(ipaddress.ip_network(c_network["network"], strict=False))
            add_ip_to_network(networks, c_network, c_ip)
    return networks


def add_ip_to_network(networks, network, ip):
    if network not in networks:
        networks[network] = []
    if ip not in networks[network]:
        networks[network].append(ip)


def actions_to_reconnect(computers: dict[str, Computer]) -> list:
    availables = []
    infected = []
    actions = []
    for ip, computer in computers.items():
        if computer.is_local:
            availables.append(ip)
        if computer.infection["infected"]:
            infected.append(
                {
                    "on": ip,
                    "via": computer.infection["via"],
                    "port": computer.infection["port"],
                }
            )
    while len(infected) != 0:
        new_availables = list(filter(lambda x: x["via"] in availables, infected))
        to_add = []
        for x in new_availables:
            infected.remove(x)
            actions.append(f"reconnect {x['on']} via {x['via']} on port {x['port']}")
        availables += map(lambda x: x["on"], new_availables)
        for infect in infected:
            network_to_find = str(ipaddress.ip_network(infect["via"], strict=False))
            for avail in availables:
                for iface in computers[avail].networks:
                    if network_to_find == str(
                        ipaddress.ip_network(iface["network"], strict=False)
                    ):
                        to_add.append(infect["on"])
                        actions.append(f"autoroute {network_to_find} via {avail}")
                        actions.append(
                            f"reconnect {infect['on']} via {infect['via']} on port {infect['port']}"
                        )
                        infected.remove(infect)
        availables += to_add
    return actions


def find_full_ip(ip: str, computers: dict[str, Computer]) -> str:
    for c_ip in computers:
        if c_ip.startswith(ip):
            return c_ip
    return ip


if __name__ == "__main__":
    c1 = Computer()
    c1.os = "Linux Mint 21.1 vera x86_64"
    c1.vulnerabilities = ["UnrealIRCD 3.2.8.1 Backdoor Command Execution"]
    c1.set_infection(True, via="192.168.155.41/24", port=4444)
    c1.add_arp_entry("192.168.155.41", "ab:cd:ef:gh:ik:kl", "wlo1")
    c1.add_arp_entry("10.0.2.6", "12:34:56:78:90:12", "et0")
    c1.add_network("wlo1", "192.168.155.130/24")
    c1.add_network("eth0", "10.0.2.5/24")
    c2 = Computer()

    to_save = {"192.168.155.130/24": c1, "10.0.2.6/24": c2}
    # save(to_save)
    loaded = load()

    print(computers_to_network(loaded))

    actions = actions_to_reconnect(loaded)
    print(actions)
    for action in actions:
        action_l = action.split(" ")
        if action_l[0] == "reconnect":
            LHOST = action_l[3].split("/")[0]
            LPORT = action_l[6]
            print(f"listen on {LHOST}:{LPORT}")
        else:
            SUBNET = action_l[1]
            SESSION = action_l[3].split("/")[
                0
            ]  # need to find IP in connected sessions to find the session number
            print(f"autoroute {SUBNET} via {SESSION}")
