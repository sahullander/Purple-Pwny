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

nm = nmap.PortScanner()

nm.scan(hosts="10.0.0.1/24", arguments='-O -sV -T4 -Pn --script vulners --exclude 10.0.0.6')

# '/' is not platform independant and neither is 'cd' #
def findModules(service, details, files, port):
    hostDir = 'cd ' + startDir[1:] + '/' + host
    outFile = service + str(port) + '.csv'
    client.consoles.console(cid).write('cd /')
    time.sleep(5)
    client.consoles.console(cid).write(hostDir) # switch into host dir if not already
    time.sleep(5)
    search = 'search ' + service + ' -S ' + details + ' type:exploit && rank:excellent || rank:good -o ' + outFile
    try:
        client.consoles.console(cid).write(search)
        time.sleep(5)
        files.append(outFile)
    except:
        pass

fields = ['Name']
for host in nm.all_hosts():
    os.system('cd / && cd ' + startDir[1:] + ' && mkdir ' + host)
    files = []
    df = pd.DataFrame(columns=fields)
    for port in nm[host]['tcp'].keys():
        service = str(nm[host]['tcp'][port]['name'])
        details = str(nm[host]['tcp'][port]['product']) + " " + str(nm[host]['tcp'][port]['version'])
        findModules(service, details, files, port)


    for file in files:
        filePath = host + "/" + file
        try:
            df1 = pd.read_csv(filePath, skipinitialspace=True, usecols=fields)
            df = df.append(df1, ignore_index=True)
        except:
            pass


    print("Exploits for host: " + host + "\n")
    print(df.head(20))

# close msfrpcd
os.system("killall ruby")
