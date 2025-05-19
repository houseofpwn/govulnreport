import json
import sys

filename = sys.argv[1]
def main():
    with open(filename, "r") as vulnfile:
        vulndata = vulnfile.read()
    newvulndata = vulndata.replace('\n',' ')
    vulnjson = json.loads(newvulndata)
    notfixedobj = {}
    fixedobj = {}
    for object in vulnjson:
        if "osv" in object:
            osv = object["osv"]
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
                        introduced = -1
                        resultobj = {}
                        for event in events:
                            if "introduced" in event:
                                introduced = event["introduced"]
                                resultobj["introduced"] = event["introduced"]
                            if "fixed" in event:
                                resultobj["fixed"] = event["fixed"]
                                fixed = True
                                #print(f'{osv["id"]} - {osv["summary"]}, {obj["package"]["name"]}, Fixed in {event["fixed"]}')

                        if fixed == False:
                            if id in notfixedobj:
                                notfixedobj[id][packagename] = resultobj
                            else:
                                notfixedobj[id] = {packagename: resultobj}
                            notfixedobj[id]["cve"] = cve

                            print(f'{osv["id"]} - {osv["summary"]}, {packagename}, NOT Fixed')
                        if fixed == True:
                            if id in fixedobj:
                                fixedobj[id][packagename] = resultobj
                            else:
                                fixedobj[id] = {packagename: resultobj}
                            fixedobj[id]["cve"] = cve


            package = affected[0]["package"]
            #print(f'{osv["id"]} - {osv["summary"]}, {package["name"]}')
    print("Loaded.")
    with open("/docs/fixed.json", 'w+') as fixedfile:
        json.dump(fixedobj, fixedfile, indent=4)
        fixedfile.close()
    with open("/docs/notfixed.json", 'w+') as notfixedfile:
        json.dump(notfixedobj, notfixedfile, indent=4)
        notfixedfile.close()



if __name__ == "__main__":
    main()
