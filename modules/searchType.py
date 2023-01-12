from modules import scrapping

class SearchTech:
    def __init__(self, techno, techID, year='', month='', minCvss=0, maxCvss=10,version=''):
        self.techno = techno
        self.year = year
        self.month = month
        self.minCvss = minCvss
        self.maxCvss = maxCvss
        self.version = version
        self.technoId = techID
