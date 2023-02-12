import bs4
import requests
import string
import time
from modules import cve, export
import urllib.parse


def exploit_query(search):
    search = urllib.parse.quote(search)
    return search


def searchOs(search,year="",minCvss="",maxCvss=""):
    search = search.lower()
    # get every OS in the top 50
    r = requests.get("https://www.cvedetails.com/top-50-products.php")
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    container = soup.find_all("table", {'class': 'listtable'})[0]
    lines = container.find_all("tr")
    # récupérer le contenu de chaque line dans un json
    count = 0  # 1 pour ignorer la premiere ligne du tableau
    linesArray = []
    for line in lines:
        array = []
        if count == 0:
            count += 1
            continue
        td = line.find_all('td')
        id = td[0].text.strip()
        name = td[1].text.strip().lower()
        url = "https://www.cvedetails.com"+line.find_all("a")[0]['href']
        array = [id,name,url]
        linesArray.append(array)
    # mtn on se débrouille pour faire la recherche
    results = []  # on initialise un tableau vide ou stockera les résultats
    print("Searching...")
    for os in linesArray:
        titleArray = os[1].split(' ')  # on coupe les valeurs dans le titre pour comparer la recherche avec
        if search in titleArray:
            r = requests.get(os[2])
            soup = bs4.BeautifulSoup(r.text,'html.parser') # on scrap pour afficher toutes les vulns du produit
            container = soup.find_all("div", {"class":"proddetailsmenu"})[0]
            url = "https://www.cvedetails.com"+container.find_all("a")[0]['href']  # +"&year="+year+"&cvssscoremin="+minCvss+"&cvssscoremax="+maxCvss
            getInfo = url.split("/")
            vendor = getInfo[4].split('-')[1]
            product = getInfo[5].split('-')[1]
            url = f"https://www.cvedetails.com/vulnerability-list.php?vendor_id={vendor}&product_id={product}&version_id=&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin={minCvss}&cvssscoremax={maxCvss}&year={year}&month=0&cweid=0&order=1&trc=7815&sha=aa65d4fbefc3f7d4b9b60af598c1cfc3ddcac06f"
            r = requests.get(url)
            soup = bs4.BeautifulSoup(r.text,'html.parser')
            try:
                error = soup.find_all("div", {"class": "errormsg"})
                if error:
                    print("No result for this search")
                    return 0
            except Exception as e:
                pass
            container = soup.find_all("table")[0]
            for line in container.find_all('tr', {'class': "srrowns"}):
                title = line.find_all('a', href=True, )[0].text
                score = line.find_all('div', {'class': "cvssbox"})[0].text
                vuln_type = line.find_all('td')[4].text.strip()
                complexity = line.find_all('td')[10].text.strip()
                pub_date = line.find_all('td')[5].text.strip()
                access = line.find_all('td')[9].text.strip()
                link = "https://www.cvedetails.com" + line.find_all('a', href=True, )[0]['href']
                array = [title,score,vuln_type,complexity,pub_date,access,link,]
                results.append(array)

    return results


def format_results(results):
    # outFile = str(time.time()) + ".csv"

    # récupérer la taille max du type de vul
    global vulnSize
    max_length = 0
    for result in results:
        curLenght = len(result[2])
        if curLenght > max_length:
            max_length = curLenght
        vulnSize = int(max_length + 2)

    print(
        "╔══════════════════╦══════╦════════╦" + "═" * vulnSize + "╦" + "═" * 9 + "╦" + "═" * 12 + "╦" + "═" * 55 + "╗")
    print("║     CVE-ID       ║Score ║complex.║" + cve.vuln_type_padding(vulnSize,
                                                                         "Vuln. Type") + "║ Access  ║ Pub Date   ║" + cve.vuln_type_padding(
        55, 'Vuln Link') + "║")
    print(
        "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╬" + "═" * 55 + "║")

    for result in results:
        print(
            "║ " + result[0].ljust(17, ' ') + "║" + cve.color_cve(result[1]) + "║" + cve.padding_complexity(result[3]) + "║" + cve.vuln_type_padding(vulnSize, result[2]) + "║" + cve.access_padding(result[5]) + "║" + cve.vuln_type_padding(12, result[4]) + "║" + cve.vuln_type_padding(55, result[6]) + "║")
        print(
            "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╬" + "═" * 55 + "╣")
        # obj = cve.CVE(result[1], result[0], result[3], result[4], result[5], result[6], result[7])
        # export.csv(outFile, obj)
    # print('exported to ' + "../outputs/" + outFile)


def getOsId(os):
    osPage = "https://www.cvedetails.com/top-50-products.php"
    r = requests.get(osPage)
    soup = bs4.BeautifulSoup(r.text, "html.parser")
    container = soup.find_all("table", {'class': 'listable'})[0]
    print(container)


# https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=PHP&queryType=phrase&search_type=all&isCpeNameSearch=false

# process :
# input techno
# get vendor ID on cve details
# search cve details with this ID
# to get page numbers: nbVuln


def getTechnoID(techno):
    baseURL = "https://www.cvedetails.com/vendor-search.php?search=" + techno
    r = requests.get(baseURL)
    try:
        soup = bs4.BeautifulSoup(r.text, 'html.parser')
        container = soup.find_all("table", {'class': "listtable"})[0]
        id = container.find_all('a', href=True, )[0]['href'].split('/')[2]
        return id
    except Exception as e:
        print(e)
        print('Nothing found')
        exit()


def scrape_cve(searchType):
    if searchType.minCvss is None:
        searchType.minCvss = 0
    if searchType.maxCvss is None:
        searchType.maxCvss = 10
    if searchType.year is None:
        searchType.year = ''

    r = requests.get(
        f"https://www.cvedetails.com/vulnerability-list.php?vendor_id={searchType.technoId}&page=1&cvssscoremin={searchType.minCvss}&cvssscoremax={searchType.maxCvss}&year={searchType.year}&month=&order=3&version_id={searchType.version}")

    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    try:
        error = soup.find_all("div", {"class": "errormsg"})
        if error:
            print("No result for this search")
            return 0
    except Exception as e:
        pass
    container = soup.find_all("table")[0]
    outFile = str(time.time()) + ".csv"
    max_length = 0
    for line in container.find_all('tr', {'class': "srrowns"}):
        vuln_type = line.find_all('td')[4].text.strip()
        current_length = len(vuln_type)
        if current_length > max_length:
            max_length = current_length
    vulnSize = int(max_length + 2)

    "╣═╔╚╝╠║"
    print(
        "╔══════════════════╦══════╦════════╦" + "═" * vulnSize + "╦" + "═" * 9 + "╦" + "═" * 12 + "╦" + "═" * 55 + "╗")
    print("║     CVE-ID       ║Score ║complex.║" + cve.vuln_type_padding(vulnSize,
                                                                         "Vuln. Type") + "║ Access  ║ Pub Date   ║" + cve.vuln_type_padding(
        55, 'Vuln Link') + "║")
    print(
        "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╬" + "═" * 55 + "║")
    # TODO Fix differenciate colors between medium & high

    # get max size of vuln_type:
    lenght = len(container)
    for line in container.find_all('tr', {'class': "srrowns"}):
        # initialize datas
        title = line.find_all('a', href=True, )[0].text
        score = line.find_all('div', {'class': "cvssbox"})[0].text
        vuln_type = line.find_all('td')[4].text.strip()
        complexity = line.find_all('td')[10].text.strip()
        pub_date = line.find_all('td')[5].text.strip()
        access = line.find_all('td')[9].text.strip()
        link = "https://www.cvedetails.com" + line.find_all('a', href=True, )[0]['href']
        # create a cve object
        obj = cve.CVE(score, title, vuln_type, complexity, pub_date, access, link)
        export.csv(outFile, obj)

        # format data for displaying
        title = title.ljust(17, ' ')
        score = cve.color_cve(score)
        vuln_type = cve.vuln_type_padding(vulnSize, vuln_type)
        complexity = cve.padding_complexity(line.find_all('td')[10].text.strip())
        pub_date = cve.vuln_type_padding(12, line.find_all('td')[5].text.strip())
        access = cve.access_padding(line.find_all('td')[9].text.strip())
        link = cve.vuln_type_padding(55, link)
        print(
            "║ " + title + "║" + score + "║" + complexity + "║" + vuln_type + "║" + access + "║" + pub_date + "║" + link + "║")
        print(
            "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╬" + "═" * 55 + "╣")
    print('exported to ' + "../outputs/" + outFile)


def search_cve(cve_id):
    r = requests.get(
        f"https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid={cve_id}+&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=")
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    container = soup.find_all("table", {'class': "searchresults"})[0]
    max_length = 0
    for line in container.find_all('tr', {'class': "srrowns"}):
        vuln_type = line.find_all('td')[4].text.strip()
        current_length = len(vuln_type)
        if current_length > max_length:
            max_length = current_length
    vulnSize = int(max_length + 2)
    if vulnSize < 12:
        vulnSize = 12
    line = container.find_all("tr", {"class": "srrowns"})[0]
    cveid = line.find_all("td")[1].text.strip().ljust(17, )
    cwe_id = line.find_all("td")[2].text.strip()
    vuln_type = cve.vuln_type_padding(vulnSize, line.find_all("td")[4].text.strip())
    date = cve.vuln_type_padding(12, line.find_all("td")[5].text.strip())
    score = cve.color_cve(line.find_all("td")[7].text.strip())
    access = cve.access_padding(line.find_all("td")[9].text.strip())
    complexity = cve.padding_complexity(line.find_all("td")[10].text.strip())
    link = cve.vuln_type_padding(55, "https://www.cvedetails.com" + line.find_all('a', href=True, )[0]['href'])

    print(
        "╔══════════════════╦══════╦════════╦" + "═" * vulnSize + "╦" + "═" * 9 + "╦" + "═" * 12 + "╦" + "═" * 55 + "╗")
    print("║     CVE-ID       ║Score ║complex.║" + cve.vuln_type_padding(vulnSize,
                                                                         "Vuln. Type") + "║ Access  ║ Pub Date   ║" + cve.vuln_type_padding(
        55, 'Vuln Link') + "║")
    print(
        "╠" + "═" * 18 + "╬" + "═" * 6 + "╬" + "═" * 8 + "╬" + "═" * vulnSize + "╬" + "═" * 9 + "╬" + "═" * 12 + "╬" + "═" * 55 + "║")

    print(
        "║ " + cveid + "║" + score + "║" + complexity + "║" + vuln_type + "║" + access + "║" + date + "║" + link + "║")
    print(
        "╚══════════════════╩══════╩════════╩" + "═" * vulnSize + "╩" + "═" * 9 + "╩" + "═" * 12 + "╩" + "═" * 55 + "╝")


def nvd_last_3_month():
    pass


if __name__ == '__main__':
    # scrape_cve(10210, 0, 10, 2022, '', 0, 0, 1)
    # getTechnoID("python")
    # search_cve("CVE-2007-1461")
    # exploit_query("php 7.4")
    # searchExploit("bluekeep")
    format_results(searchOs("debian"))
