import os
import sys
import argparse
from bs4 import BeautifulSoup


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
    a,b = "ab"
    print(a)
    print(b)
    print("args")


def menuStart():
    a, b = ""
    print(a)
    print(b)
    print("menu")


if __name__ == '__main__':
    check_args()
