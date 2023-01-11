import os
import sys
import argparse
from bs4 import BeautifulSoup
from simple_term_menu import TerminalMenu
import os
from colorama import Fore
import pyfiglet


def check_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--techno", "-t",type=str, help="Target to scan",)  # argument qui definira la target
    parser.add_argument("--os", "-o", help="choose target OS",type=str),
    parser.add_argument("--version", "-v", help="Display more information when running",type=str),
    parser.add_argument("--kcve", "-k", help="Search for a know cve",type=str)
    args = parser.parse_args()

    if args.techno or args.os or args.version or args.kcve:
        argStart(args)
    else:
        menuStart()


def argStart(args):
    print("args")


def menuStart():
    os.system('clear')
    vulnstrack = pyfiglet.figlet_format("VulnTrack", font='slant')
    main_menu_title = vulnstrack + "Main Menu :"
    main_menu_items = ["Launch!", "Two", "Settings..", "Quit"]
    main_menu_cursor = "==> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_red", "fg_yellow")
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=False,
    )

    while not main_menu_exit:
        main_sel = main_menu.show()

        if main_sel == 0:
            print("Launching VulnTrack")

        elif main_sel == 1:  # configuration menu
            print("Two")
        elif main_sel == 2:
            print("Settings")

        elif main_sel == 3:
            print(Fore.GREEN + "Quitting..." + Fore.RESET)
            quit()


if __name__ == '__main__':
    check_args()
