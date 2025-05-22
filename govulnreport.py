import json
import sys
from colorama import Fore

# This script will take the output from govulncheck json file, parses it,
# and outputs fixed.json and notfixed.json for processing by other scripts.
def main():
    filename = sys.argv[1]
    workingfolder = sys.argv[2]
    with open(filename, "r") as vulnfile:
        vulndata = vulnfile.read()
    newvulndata = vulndata.replace('\n',' ')
    vulnjson = json.loads(newvulndata)
    notfixedobj = {}
    fixedobj = {}
    for theobject in vulnjson:
        if "osv" in theobject:
            osv = theobject["osv"]
            affected = osv["affected"]
            id = osv["id"]
            cve = None
            if "aliases" in osv:
                for alias in osv["aliases"]:
                    stubs = alias.split('-')
                    if stubs[0] == "CVE":
                        cve = alias
            if len(affected) > 1:
                for obj in affected:
                    packagename = obj["package"]["name"]
                    if "ranges" in obj:
                        ranges = obj["ranges"]
                        events = ranges[0]["events"]
                        fixed = False
                        resultobj = {}
                        for event in events:
                            if "introduced" in event:
                                resultobj["introduced"] = event["introduced"]
                            if "fixed" in event:
                                resultobj["fixed"] = event["fixed"]
                                fixed = True
                        if fixed == False:
                            if id in notfixedobj:
                                notfixedobj[id][packagename] = resultobj
                            else:
                                notfixedobj[id] = {packagename: resultobj}
                            notfixedobj[id]["cve"] = cve
                        if fixed == True:
                            if id in fixedobj:
                                fixedobj[id][packagename] = resultobj
                            else:
                                fixedobj[id] = {packagename: resultobj}
                            fixedobj[id]["cve"] = cve
    print(Fore.GREEN + "Generated fixed / not-fixed tables.")
    with open(f'{workingfolder}/fixed.json', 'w+') as fixedfile:
        json.dump(fixedobj, fixedfile, indent=4)
        fixedfile.close()
    with open(f'{workingfolder}/notfixed.json', 'w+') as notfixedfile:
        json.dump(notfixedobj, notfixedfile, indent=4)
        notfixedfile.close()

if __name__ == "__main__":
    main()
