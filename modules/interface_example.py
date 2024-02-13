import re
import subprocess
import json

from textual.events import Mount
import autopwn as autopwn
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
    LoadingIndicator,
    DataTable,
    OptionList,
    Pretty,
    Button,
    Log,
    Collapsible,
)
from textual.widget import Widget
from textual import work, on, log
from textual.color import Color
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.reactive import reactive
from rich.style import Style
from rich.text import Text

STATE = {
    "client": None,  # MsfRpcClient
    "action": None,  # 0 for network scan, 1 for computer scan
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

networks = {
    "192.168.0.0/24": ["192.168.0.1", "192.168.0.5", "192.168.0.254"],
    "10.0.34.0/24": ["10.0.34.11", "10.0.34.12"],
}

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
            input.placeholder = "Enter network with mask (default: 192.168.0.0/24)"
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
        if STATE["action"] == 1:
            if not command:
                command = "192.168.0.0/24"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                input.placeholder = "Wrong format (default: 192.168.0.0/24)"
                return
            input.placeholder = "Network scan not implemented yet"
            STATE["IP"] = command
        elif STATE["action"] == 0:
            if not command:
                command = "127.0.0.1"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$").match(command):
                input.placeholder = "Wrong format (default: 127.0.0.1)"
                return
            input.placeholder = "scan started"
            STATE["IP"] = command
            self.perform_scan(STATE["IP"])

    @work(exclusive=True, thread=True)
    def perform_scan(self, IP: str) -> None:
        pretty = self.parent.query_one("#logs", Pretty)
        self.app.call_from_thread(pretty.update, "Scanning " + IP)

        result = autopwn.scanIp4Vulnerabilities(ip=IP)
        self.app.call_from_thread(pretty.update, result)

        (titles, metaexploits) = autopwn.createExploitList(result)
        titles = [title[1] for title in titles]
        STATE["vulnerabilities"] = titles

        vuln_list = self.parent.query_one("#vuln_list", OptionList)
        self.app.call_from_thread(vuln_list.clear_options)
        self.app.call_from_thread(vuln_list.add_options, titles)
        tab = self.app.query_one(Tile5)
        self.app.call_from_thread(tab.set_active_tab, "vuln_tab")
        self.app.call_from_thread(vuln_list.focus)


class Tile3(Static):

    def compose(self) -> ComposeResult:
        yield Pretty("Nothing for now", id="logs")
        # yield LoadingIndicator()

    def on_mount(self) -> None:
        self.border_title = "What is happening ?"


class Tile4(Static):
    def compose(self) -> ComposeResult:
        tree: Tree[dict] = Tree("0.0.0.0/0")
        tree.root.expand()
        for network in networks:
            network_node = tree.root.add(network, expand=True)
            for host in networks[network]:
                network_node.add_leaf(host)
        yield tree

    def on_mount(self) -> None:
        self.border_title = "Computers found"


class VulnChoice(Static):
    def compose(self) -> ComposeResult:
        with Container():
            yield OptionList(*vulnerabilities, id="vuln_list")

    @on(OptionList.OptionSelected)
    def select_vuln(self, event: OptionList.OptionSelected) -> None:
        STATE["vulnerability"] = event.option_index
        modules = autopwn.searchModules(
            STATE["client"], STATE["vulnerabilities"][event.option_index][:-12]
        )
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
        self.app.call_from_thread(self.app.query_one(Tile5).set_active_tab, "shell_tab")
        self.app.call_from_thread(self.app.query_one("#shells_list", ListView).focus)
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

    def add_shell(
        self, shell_id: str, tunnel_local: str, tunnel_peer: str, base_log: str = ""
    ) -> None:
        """Add one shell, possibility to add a base text"""
        shellsList = self.query_one(ListView)
        new_entry = ListItem(
            Collapsible(
                Input(placeholder="command"),
                Log(),
                title=f"Shell {shell_id}, {tunnel_local} -> {tunnel_peer}",
            )
        )
        shellsList.append(new_entry)

    def remove_shell(self, shell_id: str) -> None:
        """Remove one shell from the list by it's id"""
        shellsList = self.query_one(ListView)
        shellsInfo = self.get_shells_info()

        shellsList.clear()
        for id, shell in shellsInfo.items():
            if id != shell_id:
                self.add_shell(
                    id,
                    shell["tunnel_local"],
                    shell["tunnel_peer"],
                    base_log=shell["base_log"],
                )

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
        shellsList.clear()
        for id, shell in current_shells.items():
            self.add_shell(
                id,
                shell["tunnel_local"],
                shell["tunnel_peer"],
                base_log=shell["base_log"],
            )

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
        client: MsfRpcClient = STATE["client"]
        shell: ShellSession = client.sessions.session(id)
        shell.write(cmd)
        self.update_shell_log(shell, log)

    @work(thread=True)
    def update_shell_log(self, shell: ShellSession, log: Log) -> None:
        s = shell.read()
        while not s:
            s = shell.read()
        self.app.call_from_thread(log.write_line, s)


class Tile5(Static):
    def compose(self) -> ComposeResult:
        with TabbedContent():
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

    def on_mount(self) -> None:
        self.border_title = "Exploitation"

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
        client = autopwn.runMetasploit(reinit=True, show=False)
        STATE["client"] = client
        self.app.call_from_thread(self.end_init)

    def end_init(self):
        self.sub_title = "ready for pwn"


if __name__ == "__main__":
    app = Pwnguin()
    app.run()
    subprocess.run("kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True)
