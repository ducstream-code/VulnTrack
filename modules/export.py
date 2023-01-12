

def csv(outputname,cve):
    file = open("../outputs/"+outputname,'a')
    line = f"{cve.ID};{cve.score};{cve.complexity};{cve.access};{cve.pub_date}\n"
    file.writelines(line)
    file.close()