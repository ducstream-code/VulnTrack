import os
import sys
import argparse
from modules import searchType, scrapping


def check_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--techno", "-t", type=str, help="Defini techno to scan", )  # argument qui definira la target
    group.add_argument("--os", "-o", help="choose target OS", type=str),
    parser.add_argument("--version", "-v", help="Display more information when running", type=str),
    parser.add_argument("--mincvss", "-L", help="Set the low limit for cvss", type=str),
    parser.add_argument("--maxcvss", "-H", help="Set the high limit for cvss", type=str),
    group.add_argument("--cve", "-c", help="Search for a know cve", type=str)
    group.add_argument("--year", "-y", help="Search for a know cve", type=str)
    args = parser.parse_args()

    if args.techno or args.os or args.cve:
        argStart(args)
    else:
        menuStart()


def argStart(args):
    if args.techno:
        techSearch = searchType.SearchTech('args.techno', scrapping.getTechnoID(args.techno), year=args.year,
                                           maxCvss=args.maxcvss, minCvss=args.mincvss)
        try:
            scrapping.scrape_cve(techSearch)
        except Exception as e:
            print('Nothing found')
        pass
    elif args.cve:
        try:
            scrapping.search_cve(args.cve)
        except Exception as e:
            print('Nothing found')


def menuStart():
    print("menu")


if __name__ == '__main__':
    check_args()
