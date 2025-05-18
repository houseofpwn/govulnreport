import json
import sys

filename = sys.argv[1]
def main():
    print(f'{filename}')
    with open(filename, "r") as vulnfile:
        vulndata = vulnfile.read()
    newvulndata = vulndata.replace('\n',' ')
    vulnjson = json.loads(newvulndata)
    for object in vulnjson:
        if "osv" in object:
            osv = object["osv"]
            affected = osv["affected"]
            if len(affected) > 1:
                for obj in affected:
                    if "ranges" in obj:
                        ranges = obj["ranges"]
                        events = ranges[0]["events"]
                        fixed = False
                        for event in events:
                            if "fixed" in event:
                                fixed = True
                                #print(f'{osv["id"]} - {osv["summary"]}, {obj["package"]["name"]}, Fixed in {event["fixed"]}')

                        if fixed == False:
                            print(f'{osv["id"]} - {osv["summary"]}, {obj["package"]["name"]}, NOT Fixed')
            package = affected[0]["package"]
            #print(f'{osv["id"]} - {osv["summary"]}, {package["name"]}')
    print("Loaded.")



if __name__ == "__main__":
    main()
