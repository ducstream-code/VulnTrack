from colorama import Fore


class CVE:
    def __init__(self, score, ID, vuln_type, complexity, pub_date,access):
        self.score = score
        self.ID = ID
        self.vuln_type = vuln_type
        self.complexity = complexity
        self.pub_date = pub_date
        self.access = access

    def get_score(self):
        print(self.score)
        return self.score

    def get_ID(self):
        print(self.ID)
        return self.ID

    def get_vulnType(self):
        print(self.vuln_type)
        return self.vuln_type

    def get_complexity(self):
        print(self.complexity)
        return self.complexity

    def get_pub_date(self):
        print(self.pub_date)
        return self.pub_date


def color_cve(score):
    if 0.1 <= float(score) <= 3.9:
        score = Fore.GREEN + " " + score + "  " + Fore.RESET
        return score
    elif 4 <= float(score) <= 6.9:
        score = Fore.LIGHTYELLOW_EX + " " + score + "  " + Fore.RESET
        return score
    elif 7 <= float(score) <= 8.9:
        score = Fore.YELLOW + " " + score + "  " + Fore.RESET
        return score
    elif 9 <= float(score) <= 9.9:
        score = Fore.RED + " " + score + "  " + Fore.RESET
        return score
    elif 9.9 < float(score) <= 10:
        score = Fore.RED + " " + score + " " + Fore.RESET
        return score
    else:
        score = Fore.LIGHTBLACK_EX + " " + score + " " + Fore.RESET
        return score


def padding_complexity(comp):
    if comp == "Low":
        return Fore.GREEN+" Low    "+Fore.RESET
    if comp == "Medium":
        return Fore.YELLOW+" Medium "+Fore.RESET
    if comp == "High":
        return Fore.RED+" High   "+Fore.RESET
    else: return Fore.LIGHTBLACK_EX+" ???    "+Fore.RESET


def vuln_type_padding(padding,vulnType):
    vulnType = " "+ vulnType
    vulnType = vulnType.ljust(padding, " ")
    return vulnType


def access_padding(access):
    access = " "+ access
    access = access.ljust(9, " ")
    return access
