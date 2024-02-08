from time import monotonic

from textual.app import App, ComposeResult
from textual.widgets import (
    Button,
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
)
from textual.containers import Container
from textual.containers import ScrollableContainer
from textual.color import Color
from textual.reactive import reactive
from rich.table import Table
from rich.text import Text

vulnerabilities = [
    "vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption",
    "vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)",
    "vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)",
    "vsftpd 2.3.2 - Denial of Service",
    "vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)",
    "vsftpd 2.3.4 - Backdoor Command Execution",
    "vsftpd 3.0.3 - Remote Denial of Service",
    "vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)",
    "vsftpd 2.3.4 - Backdoor Command Execution",
    "Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation",
    "Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service",
    "FreeBSD OpenSSH 3.5p1 - Remote Command Execution",
    "glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read",
    "Novell Netware 6.5 - OpenSSH Remote Stack Overflow",
    "OpenSSH 1.2 - '.scp' File Create/Overwrite",
    "OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)",
    "OpenSSH 2.3 < 7.7 - Username Enumeration",
    "OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One",
    "OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow",
    "OpenSSH 3.x - Challenge-Response Buffer Overflow (1)",
    "OpenSSH 3.x - Challenge-Response Buffer Overflow (2)",
    "OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service",
    "OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation",
    "OpenSSH 7.2 - Denial of Service",
    "OpenSSH 7.2p1 - (Authenticated) xauth Command Injection",
    "OpenSSH < 6.6 SFTP (x64) - Command Execution",
    "OpenSSH < 6.6 SFTP - Command Execution",
    "OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation",
    "OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading",
    "OpenSSH < 7.7 - User Enumeration (2)",
    "OpenSSH SCP Client - Write Arbitrary Files",
    "OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident",
    "OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool",
    "OpenSSHd 7.2p2 - Username Enumeration",
    "Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack",
]

exploits = [
    ["exploit path", "quality", "description"],
    [
        "exploit/osx/local/setuid_tunnelblick",
        "excellent",
        "Setuid Tunnelblick Privilege Escalation",
    ],
    [
        "exploit/multi/http/sflog_upload_exec",
        "excellent",
        "Sflog! CMS 1.0 Arbitrary File Upload Vulnerability",
    ],
    [
        "exploit/windows/fileformat/shadow_stream_recorder_bof",
        "normal",
        "Shadow Stream Recorder 3.0.1.7 Buffer Overflow",
    ],
    [
        "exploit/windows/http/sharepoint_data_deserialization",
        "excellent",
        "SharePoint DataSet / DataTable Deserialization",
    ],
    [
        "exploit/windows/http/sharepoint_workflows_xoml",
        "excellent",
        "SharePoint Workflows XOML Injection",
    ],
    [
        "exploit/windows/misc/shixxnote_font",
        "great",
        "ShixxNOTE 6.net Font Field Overflow",
    ],
    [
        "exploit/multi/http/shopware_createinstancefromnamedarguments_rce",
        "excellent",
        "Shopware createInstanceFromNamedArguments PHP Object Instantiation RCE",
    ],
    [
        "exploit/windows/scada/winlog_runtime",
        "great",
        "Sielco Sistemi Winlog Buffer Overflow",
    ],
    [
        "exploit/windows/scada/winlog_runtime_2",
        "normal",
        "Sielco Sistemi Winlog Buffer Overflow 2.07.14 - 2.07.16",
    ],
    [
        "exploit/windows/scada/factorylink_csservice",
        "normal",
        "Siemens FactoryLink 8 CSService Logging Path Param Buffer Overflow",
    ],
    [
        "exploit/windows/scada/factorylink_vrn_09",
        "average",
        "Siemens FactoryLink vrn.exe Opcode 9 Buffer Overflow",
    ],
    [
        "exploit/windows/browser/siemens_solid_edge_selistctrlx",
        "normal",
        "Siemens Solid Edge ST4 SEListCtrlX ActiveX Remote Code Execution",
    ],
    [
        "exploit/multi/http/simple_backdoors_exec",
        "excellent",
        "Simple Backdoor Shell Remote Code Execution",
    ],
    [
        "exploit/unix/webapp/simple_e_document_upload_exec",
        "excellent",
        "Simple E-Document Arbitrary File Upload",
    ],
    [
        "exploit/unix/webapp/sphpblog_file_upload",
        "excellent",
        "Simple PHP Blog Remote Command Execution",
    ],
    [
        "exploit/windows/http/sws_connection_bof",
        "normal",
        "Simple Web Server Connection Header Buffer Overflow",
    ],
    [
        "exploit/windows/http/sitecore_xp_cve_2021_42237",
        "excellent",
        "Sitecore Experience Platform (XP) PreAuth Deserialization RCE",
    ],
    [
        "exploit/unix/webapp/sixapart_movabletype_storable_exec",
        "good",
        "SixApart MovableType Storable Perl Code Execution",
    ],
    [
        "exploit/unix/webapp/skybluecanvas_exec",
        "excellent",
        "SkyBlueCanvas CMS Remote Code Execution",
    ],
    [
        "exploit/windows/ftp/slimftpd_list_concat",
        "great",
        "SlimFTPd LIST Concatenation Overflow",
    ],
    [
        "exploit/windows/http/smartermail_rce",
        "excellent",
        "SmarterTools SmarterMail less than build 6985 - .NET Deserialization Remote Code Execution",
    ],
]

payloads = [
    ["payload path"],
    ["payload/aix/ppc/shell_bind_tcp"],
    ["payload/aix/ppc/shell_find_port"],
    ["payload/aix/ppc/shell_reverse_tcp"],
    ["payload/aix/ppc/shell_interact"],
    ["payload/cmd/unix/adduser"],
    ["payload/android/meterpreter_reverse_http"],
    ["payload/android/meterpreter_reverse_https"],
    ["payload/android/meterpreter_reverse_tcp"],
    ["payload/android/meterpreter/reverse_http"],
    ["payload/android/meterpreter/reverse_https"],
    ["payload/android/meterpreter/reverse_tcp"],
    ["payload/osx/armle/shell_bind_tcp"],
    ["payload/osx/armle/shell_reverse_tcp"],
    ["payload/apple_ios/aarch64/shell_reverse_tcp"],
    ["payload/osx/armle/vibrate"],
    ["payload/apple_ios/aarch64/meterpreter_reverse_http"],
    ["payload/apple_ios/armle/meterpreter_reverse_http"],
    ["payload/apple_ios/aarch64/meterpreter_reverse_https"],
    ["payload/apple_ios/armle/meterpreter_reverse_https"],
    ["payload/apple_ios/aarch64/meterpreter_reverse_tcp"],
    ["payload/apple_ios/armle/meterpreter_reverse_tcp"],
]

networks = {
    "192.168.0.0/24": ["192.168.0.1", "192.168.0.5", "192.168.0.254"],
    "10.0.34.0/24": ["10.0.34.11", "10.0.34.12"],
}


class Tile1(Static):
    def on_mount(self) -> None:
        self.border_title = "Action Type"
        self.update("- Scan network\n- Scan computer")


class Tile2(Static):

    def compose(self) -> ComposeResult:
        yield Input()

    def on_mount(self) -> None:
        self.border_title = "Input"


class Tile3(Static):

    def compose(self) -> ComposeResult:
        yield Static("nmap scan")
        yield LoadingIndicator()

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
        with ListView():
            for vuln in vulnerabilities:
                yield ListItem(Label(vuln))


class ExploitMenu(Static):
    def compose(self) -> ComposeResult:
        yield DataTable()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(*exploits[0])
        for row in exploits[1:]:
            # Adding styled and justified `Text` objects instead of plain strings.
            styled_row = [
                Text(str(cell), style="italic #03AC13", justify="left") for cell in row
            ]
            table.add_row(*styled_row)


class PayloadMenu(Static):
    def compose(self) -> ComposeResult:
        yield DataTable()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(*payloads[0])
        for row in payloads[1:]:
            # Adding styled and justified `Text` objects instead of plain strings.
            styled_row = [
                Text(str(cell), style="italic #03AC13", justify="left") for cell in row
            ]
            table.add_row(*styled_row)


class Tile5(Static):

    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Vulnerabilities"):
                yield VulnChoice()
            with TabPane("Exploit Menu"):
                yield ExploitMenu()
            with TabPane("Payload Menu"):
                yield PayloadMenu()

    def on_mount(self) -> None:
        self.border_title = "Exploitation"


class Pwnguin(App):
    BINDINGS = [
        ("ctrl+t", "toggle_dark", "Toggle dark mode"),
    ]
    CSS_PATH = "interface.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="grid"):
            yield Tile1(classes="tile", id="tile1")
            yield Tile2(classes="tile", id="tile2")
            yield Tile3(classes="tile", id="tile3")
            yield Tile4(classes="tile", id="tile4")
            yield Tile5(classes="tile", id="tile5")
        yield Footer()


if __name__ == "__main__":
    app = Pwnguin()
    app.run()
