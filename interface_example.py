import re
import subprocess
import json
import time
from pymetasploit3.msfrpc import MsfRpcClient, ExploitModule, PayloadModule


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
)
from textual import work, on, log
from textual.color import Color
from textual.containers import Container, Horizontal
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

actions = ["Scan network", "Scan computer"]


def perform_scan(IP: str) -> None:
    CMD = (
        "./modules/explookup.sh " + IP + ""
    )  # Sortie standard dans /dev/null pour la lisibilité, à changer
    scan = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE, text=True)
    lines = []
    while scan.poll() is None:
        s = scan.stdout.readline()
        if s:
            lines += [s]
            app.call_from_thread(app.query_one("#logs", Pretty).update, lines)


class Tile1(Static):

    def compose(self) -> ComposeResult:
        yield OptionList(*actions)

    def on_mount(self) -> None:
        self.border_title = "Action Type"

    @on(OptionList.OptionHighlighted)
    def show_selected(self, event: OptionList.OptionHighlighted) -> None:
        input = self.parent.query_one("#command", Input)
        if event.option_index == 0:
            input.placeholder = "Enter network with mask (default: 192.168.0.0/24)"
        elif event.option_index == 1:
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
                command = "192.168.0.0/24"
            if not re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$").match(
                command
            ):
                input.placeholder = "Wrong format (default: 192.168.0.0/24)"
                return
            input.placeholder = "Network scan not implemented yet"
            STATE["IP"] = command
        elif STATE["action"] == 1:
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
        perform_scan(IP)
        EXPLOIT_LIST = "./exploit_list"
        with open(EXPLOIT_LIST, "r") as f:
            result = json.loads(f.read())
        self.app.call_from_thread(pretty.update, result)

        # Create exploits from the list of research
        exploits = []
        for search in result:
            exploits += search["RESULTS_EXPLOIT"]
        titles = [pwn["Title"] for pwn in exploits]
        titles = list(set(titles))

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
        client: MsfRpcClient = STATE["client"]
        modules = client.modules.search(
            STATE["vulnerabilities"][event.option_index][:-12]
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
        client: MsfRpcClient = STATE["client"]
        exploit_ms = client.modules.use(exploit["type"], exploit["fullname"])
        STATE["exploit_ms"] = exploit_ms
        payloads = exploit_ms.targetpayloads()
        STATE["payloads"] = payloads
        payloadsList = self.app.query_one("#payload_list", OptionList)
        payloadsList.clear_options()
        payloadsList.add_options([Text(payload) for payload in payloads])
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
        client: MsfRpcClient = STATE["client"]
        payload_ms = client.modules.use("payload", payload)
        STATE["payload_ms"] = payload_ms
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
            if param_name in STATE["exploit_ms"].missing_required:
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
                yield ParamMenu("Exploit")

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
        proc = subprocess.run(
            "msfrpcd -P yourpassword", shell=True, stderr=subprocess.DEVNULL
        )
        proc = subprocess.run(
            "echo 'yes' | msfdb reinit",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # if db problem
        STATE["client"] = MsfRpcClient("yourpassword", ssl=True)
        self.app.call_from_thread(self.end_init)

    def end_init(self):
        self.sub_title = "ready for pwn"


if __name__ == "__main__":
    app = Pwnguin()
    app.run()
    subprocess.run("kill $(ps aux | grep 'msfrpcd' | awk '{print $2}')", shell=True)
