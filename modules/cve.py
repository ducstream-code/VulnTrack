class CVE:
    def __int__(self, score, ID, vuln_type, complexity, pub_date):
        self.score = score
        self.ID = ID
        self.vuln_type = vuln_type
        self.complexity = complexity
        self.pub_date = pub_date

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