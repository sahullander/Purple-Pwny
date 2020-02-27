##-------- Use this code for setting cve score = weighted avg of all services weighted averages --------##
for host in nm.all_hosts():
	cveCount = 0 # get len(tabs) / 3 for each port and add to cveCount
	hostCVEAvg = [] # get weighted average for each port and append to this list
	hostCVEScore = 0 # weighted average of hostCVEAvg
	f.write("\n\nResults for IP: {0}\n".format(host))
	try:
		OS = nm[host]['osmatch'][0]['name']
		f.write("OS: {0}\n".format(OS))
	except:
		f.write("OS: Not Found\n")
	try:
		f.write("Port    Service                  Details \n")
		for port in nm[host]['tcp'].keys():
			service = str(port).ljust(8," ") + nm[host]['tcp'][port]['name'].ljust(25, " ") + nm[host]['tcp'][port]['product'] + " " + nm[host]['tcp'][port]['version']
			f.write(service + '\n')
			try:
				#--------- Gets score (as float) of each CVE only ---------#
				tabs = []
				cveScoreList = []
				start = 1
				for m in re.finditer('\t', nm[host]['tcp'][port]['script']['vulners']):
					tabs.append(m.start())
				cveCount = cveCount + (len(tabs) / 3)
				while start <= len(tabs)-2:
					cveScoreList.append(float(nm[host]['tcp'][port]['script']['vulners'][tabs[start]+1:tabs[start+1]]))
					start += 3
				#--- Gets weighted avg. CVE score for this service ---#
				numerator = 0
				denominator = sum(cveScoreList)
				for score in cveScoreList:
					numerator = numerator + (score * score)
				serviceAvgScore = numerator / denominator
				hostCVEAvg.append(serviceAvgScore)
			except:
				pass
            ### Use this if you want to print CVE details for each service ###
			try:
				f.write(nm[host]['tcp'][port]['script']['vulners'] + '\n')
			except:
				pass
	except:
		pass
	#-- Weighted avg. of CVEs for host --#
	if len(hostCVEAvg) > 0:
		hostNumerator = 0
		hostDenominator = sum(hostCVEAvg)
		for average in hostCVEAvg:
			hostNumerator = hostNumerator + (average * average)
		hostCVEScore = hostNumerator / hostDenominator
	else:
		pass
	thisHost = {"IP":host,"CVEScore":hostCVEScore, "CVECount":cveCount}
	hostObjects.append(thisHost)
	f.write("Host statistics: {0}\n".format(thisHost))
