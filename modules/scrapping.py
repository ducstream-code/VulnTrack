import bs4
import requests
import string
import time
from modules import cve, export


# https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=PHP&queryType=phrase&search_type=all&isCpeNameSearch=false

# process :
# input techno
# get vendor ID on cve details
# search cve details with this ID
# to get page numbers: nbVuln


def getTechnoID(techno):
    baseURL = "https://www.cvedetails.com/vendor-search.php?search=" + techno
    r = requests.get(baseURL)
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    container = soup.find_all("table", {'class': "listtable"})[0]
    id = container.find_all('a', href=True, )[0]['href'].split('/')[2]
    return id


def scrape_cve(searchType):
    if searchType.minCvss is None:
        searchType.minCvss = 0
    if searchType.maxCvss is None:
        searchType.maxCvss = 10
    if searchType.year is None:
        searchType.year = ''

    # r = requests.get(f"http://www.cvedetails.com/vulnerability-list.php?vendor_id={vendorId}&product_id={product_id}&version_id={version_id}&page={page}&cvssscoremin={minScore}&cvssscoremax={maxScore}&year={year}&month={month}&order=3")
    # r = requests.get(f"https://www.cvedetails.com/vulnerability-list.php?vendor_id=10210&page=1&cvssscoremin=0&cvssscoremax=10&year=2022&month=&order=3")
    # url = f"https://www.cvedetails.com/vulnerability-list.php?vendor_id={searchType.technoId}&page=1&cvssscoremin={searchType.minCvss}&cvssscoremax={searchType.maxCvss}&year={searchType.year}&month=&order=3"
    #print(url)
    r = requests.get(
        f"https://www.cvedetails.com/vulnerability-list.php?vendor_id={searchType.technoId}&page=1&cvssscoremin={searchType.minCvss}&cvssscoremax={searchType.maxCvss}&year={searchType.year}&month=&order=3")
    # print(r.text)

    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    container = soup.find_all("table")[0]
    # print(container.text)
    outFile = str(time.time()) + ".csv"
    max_length = 0
    for line in container.find_all('tr', {'class': "srrowns"}):
        vuln_type = line.find_all('td')[4].text.strip()
        current_length = len(vuln_type)
        if current_length > max_length:
            max_length = current_length
    vulnSize = int(max_length + 2)

    "╣═╔╚╝╠║"
    print("╔══════════════════╦══════╦════════╦" + "═" * vulnSize + "╦" + "═" * 9 + "╦" + "═" * 12 + "╗")
    print("║     CVE-ID       ║Score ║complex.║"+cve.vuln_type_padding(vulnSize,"Vuln. Type")+"║ Access  ║ Pub Date   ║")
    print("╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╣")
    # TODO Fix differenciate colors between medium & high

    # get max size of vuln_type:

    for line in container.find_all('tr', {'class': "srrowns"}):
        # initialize datas
        title = line.find_all('a', href=True, )[0].text

        score = line.find_all('div', {'class': "cvssbox"})[0].text
        vuln_type = line.find_all('td')[4].text.strip()
        complexity = line.find_all('td')[10].text.strip()
        pub_date = line.find_all('td')[5].text.strip()
        access = line.find_all('td')[9].text.strip()

        # create a cve object
        obj = cve.CVE(score, title, vuln_type, complexity, pub_date, access)
        export.csv(outFile, obj)

        # format data for displaying
        title = title.ljust(17, ' ')
        score = cve.color_cve(score)
        vuln_type = cve.vuln_type_padding(vulnSize, vuln_type)
        complexity = cve.padding_complexity(line.find_all('td')[10].text.strip())
        pub_date = cve.vuln_type_padding(12, line.find_all('td')[5].text.strip())
        access = cve.access_padding(line.find_all('td')[9].text.strip())

        print("║ " + title + "║" + score + "║" + complexity + "║" + vuln_type + "║" + access + "║" + pub_date + "║")
        print(
            "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╣")
    print('exported to ' + "../outputs/" + outFile)
def test(a=0, b=0, c=0):
    x = a + b + c
    print(x)


if __name__ == '__main__':
    # scrape_cve(10210, 0, 10, 2022, '', 0, 0, 1)
    getTechnoID("python")
