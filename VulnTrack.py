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
    parser.add_argument("--year", "-y", help="Search for a know cve", type=str)
    args = parser.parse_args()

    if args.techno or args.os or args.cve:
        argStart(args)
    else:
        menuStart()


def argStart(args):
    if args.techno:
        techSearch = searchType.SearchTech(args.techno, scrapping.getTechnoID(args.techno), year=args.year,
                                           maxCvss=args.maxcvss, minCvss=args.mincvss)
        try:
            scrapping.scrape_cve(techSearch)
        except Exception as e:
            print(e)
            print('Nothing found')
        pass
    elif args.cve:
        try:
            scrapping.search_cve(args.cve)
        except Exception as e:
            # print(e)
            print('Nothing found')
    elif args.os:
        try:
            print("Due to few sources for OS CVE, it is only possible to scrap for the 50 most common OS.\n But it can take a while if the search is not precise")
            params = searchType.SearchOs(args.os, year=args.year, maxCvss=args.maxcvss, minCvss=args.mincvss)
            res = scrapping.searchOs(params.os,params.year,params.minCvss,params.maxCvss)
            scrapping.format_results(res)
        except Exception as e:
            # print(e)
            print("nothing found")


def menuStart():
    print("menu")


if __name__ == '__main__':
    check_args()
