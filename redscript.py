import nmap
import socket
import struct
import os
import ipaddress
import re
import random, string
from ftplib import FTP
from datetime import datetime
import netifaces
import platform

startTime = datetime.now()

# Open file for writing our output and create if its not created already
f = open("overview.txt","a+")

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

# Cross Platform way to get the following info but uses 2 imports
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

print(subnet)
# Just a prompt for the output file
f.write('\nInitiating quick scan from host {0} to {1} \n'.format(subnet[0], subnet[-1]))

######## NMAP STUFF ########
nm.scan(hosts=str(subnet), arguments='-O -sV --script vulners')

hostsCount = len(nm.all_hosts())
hostObjects = []
f.write("Count of alive hosts: {0}\n".format(hostsCount))
f2 = open("IPList.txt","a+")
f2.write('\n'.join(map(str,nm.all_hosts())))
f2.close()

f3 = open("serviceDetails.txt","a+")
f4 = open("cveDetails.txt","a+")

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
	countMSMod = 0 # total number of Metasploit Modules found
	countNoCVEports = 0 # used to determine when to print "No CVEs for this host." (ie when no servies found or no CVEs found)

	# We can print all of this later after the objects are sorted
	# f.write("\n\nResults for IP: {0}\n".format(host))
	try:
		OS = nm[host]['osmatch'][0]['name']
	except:
		 OS = 'No OS Found'
	f3.write("\nIP: {0}".format(host))
	f4.write("IP: {0}\n\t".format(host))
	try:
		f3.write("\nPort    Service                  Details")
		for port in nm[host]['tcp'].keys():
			service = str(port).ljust(8," ") + nm[host]['tcp'][port]['name'].ljust(25, " ") + nm[host]['tcp'][port]['product'] + " " + nm[host]['tcp'][port]['version']
			f3.write('\n\t' + service)
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
					f4.write(nm[host]['tcp'][port]['script']['vulners'] + '\n')
				except:
					pass
			except:
				countNoCVEports += 1
				if countNoCVEports == len(nm[host]['tcp'].keys()):
					f4.write("No CVEs for this host.\n")
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

	thisHost = {"IP":host, "Severity":severity, "SeverityNum":severityNum, "MSMods":countMSMod, "Criticals":countCritical, "Highs":countHigh, "Mediums":countMedium, "Lows":countLow, "Nones":countNone, "CVECount":cveCount, "OS":OS}
	hostObjects.append(thisHost)
f3.close()
for sys in hostObjects:
	print(sys)
	print("\n")

print("NOW THEY ARE SORTED!!")
hostObjects.sort(key = lambda l: (l["SeverityNum"], l["Criticals"], l["Highs"], l["Mediums"], l["Lows"], l["Nones"]), reverse = True)
printed4 = False
printed3 = False
printed2 = False
printed1 = False
printed0 = False
printedNeg = False

for sys in hostObjects:
	if sys["SeverityNum"] == 4:
		if printed4 == False:
			printed4 = True
			f.write("\n--- Vulnerability Level: Critical ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
	elif sys["SeverityNum"] == 3:
		if printed3 == False:
			printed3 = True
			f.write("\n--- Vulnerability Level: High ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))

		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
	elif sys["SeverityNum"] == 2:
		if printed2 == False:
			printed2 = True
			f.write("\n--- Vulnerability Level: Medium ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
	elif sys["SeverityNum"] == 1:
		if printed1 == False:
			printed1 = True
			f.write("\n--- Vulnerability Level: Low ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
	elif sys["SeverityNum"] == 0:
		if printed0 == False:
			printed0 = True
			f.write("\n--- Vulnerability Level: None ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
	elif sys["SeverityNum"] == -1:
		if printedNeg  == False:
			printedNeg = True
			f.write("\n--- Vulnerability Level: Inconclusive ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))
		else:
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"]))

"""
nc['10.0.0.42']['tcp'][80]['script']['vulners']
print(nm['192.168.1.1']['addresses']['mac'])
## gets OS possibilities (a list of dictionaries) ##
##### it looks like the first dictionary returned has the highest #####
##### 'accuracy' value however example I ran the first one was wrong... #####
nm['10.0.0.42']['osmatch']
## prints all details for a particular OS name including accuracy etc
next(item for item in nm['10.0.0.42']['osmatch'] if item['name'] == 'Microsoft Windows 10 1607')
## prints value associated with key (here its 'name') for a paricular OS name
next(item['name'] for item in nm['10.0.0.42']['osmatch'] if item['name'] == 'Microsoft Windows 10 1607')
# get all open ports
nm['10.0.0.42']['tcp'].keys()
# save and then print all services on different lines
services = [nm['10.0.0.42']['tcp'][item]['name'] for item in nm['10.0.0.42']['tcp'].keys()]
print('\n'.join(map(str, services)))
# get service running on port
nm['10.0.0.42']['tcp'][135]['name']
# get version of service of applicable
nm['10.0.0.42']['tcp'][135]['product'] + nm['10.0.0.42']['tcp'][135]['version']
# prints all services
print([nm['10.0.0.42']['tcp'][item]['name'] for item in nm['10.0.0.42']['tcp'].keys()])
"""

endTime = datetime.now()
runtime = endTime-startTime
f.write('\n\n End Script @ {0}    ---   Total Runtime: {1}'.format(endTime, runtime))
f.close()
