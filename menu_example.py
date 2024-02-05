from time import sleep
from simple_term_menu import TerminalMenu
import re


def scanReseau():
    reseau = input(
        "Entrez l'adresse IP/masque du réseau à scanner:",
    )
    reseau = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$", reseau).string
    if not reseau:
        print("Erreur: Adresse réseau non valide")
        return
    print(f"Scan du réseau {reseau} ...")
    options = ["192.168.0.1", "192.168.0.2", "192.168.0.3"]
    terminal_menu = TerminalMenu(
        options, title="Machines détéctées ! Laquelle attaquer ?"
    )
    menu_entry_index = terminal_menu.show()
    if menu_entry_index is None:
        return
    ip_machine = options[menu_entry_index]
    scanMachine(ip_machine)


def scanMachine(ip_machine: str):
    print(f"Scan de la machine {ip_machine} ...")
    options = ["22", "80", "443"]
    terminal_menu = TerminalMenu(
        options,
        title="Ports ouvert détécté ! Lequel/Lesqels attaquer ?",
        multi_select=True,
    )
    menu_entry_index = terminal_menu.show()
    if not menu_entry_index:
        return
    for i in menu_entry_index:
        print(f"Attaque du port {options[i]} en cours...")
        sleep(2)
    print("Attaque terminée !")
    print("shell root disponible !")


def main():
    options = ["Scanner un Réseau", "Attaquer une machine spécifique"]
    terminal_menu = TerminalMenu(options, title="Que voulez-vous faire ?")
    menu_entry_index = terminal_menu.show()
    if menu_entry_index is None:
        exit(0)
    print(f"{options[menu_entry_index]}!")
    match menu_entry_index:
        case 0:
            scanReseau()
        case 1:
            ip_machine = input("Entrez l'adresse IP de la machine à attaquer:")
            ip_machine = re.search(
                r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_machine
            ).string
            if not ip_machine:
                print("Erreur: Adresse IP non valide")
                return
            scanMachine(ip_machine)
        case _:
            print("Erreur: Option non valide")
            exit(1)


if __name__ == "__main__":
    while 1:
        main()
