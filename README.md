# Purple-Pwny

![PPP](https://imgur.com/Sh86dxd.png)

Automated Purple Team Script

## Overview
The idea behind this script is simple: Rank hosts on a given subnet and attempt to exploit them using Metasploit modules without the need of an operator. Simply put, a user with no penetration testing or vulnerability assessment experience can run this script and gain knowledge about weaknesses in the systems connected to the network. The ideal user is a red (offensive) team or blue (defensive) team member, hence the "purple" in "Purple-Pwny". "Pwn" in that name is a slang term for 'defeating' or 'to get the better of' something else, in this case another system. Pwn was morphed into Pwny for no reason other than "Purple-Pwn" just didn't seem fitting enough, and let's face it, all scripts needed a good mascot! 

Video demonstration here: https://youtu.be/-kpJbzc2gzM

## Prerequisites
The idea was to limit the number of external dependecies as much as possible, however a few non-standard libraries were used. Below is a simple guide that will allow you to install and test the script out. For the time-being, this script does not work in Windows enviroments. This is something that will be worked on as time goes on and demand calls for it.
  1. install python3.7.6 (other versions may work, but have not tested)
  2. `sudo pip3 install python-nmap, pymetasploit3, netifaces, pandas`
  3. `git clone https://github.com/sahullander/Purple-Pwny.git`

## Executing the script
Executing the python script is easy. Change into the directory where "purplepwny.py" exists (inside the Purple-Pwny folder if you used git to download the script). Then run `sudo python3 purplepwny.py -h` to see a list of available options detailed below.

![github-small](https://imgur.com/Boa7d6H.png)
  
## Example Output
There are 4 .txt output files: IPList.txt, serviceDetails.txt, cveDetails.txt, and overview.txt. Examples for each of these can be found in the "OutputSamples" folder
   
  #### IPList.txt
  This file simply list all IPv4 addresses of alive hosts on the network.
  
  ![github-small](https://imgur.com/GGcu9px.png)
    
  #### serviceDetails.txt
  This file provides a nmap-like output of services for each host. Information includes: host IPv4 address, ports, service name, service product, and service version.
  
  ![github-small](https://imgur.com/Iod7uCR.png)
    
  #### cveDetails.txt
  This file provides information regarding to each CVE found during the scan. Each host shows the port and associated CVEs for the service running on that port. CVE details include the CVE name, rank, and a link to read about the CVE.
  
 ![github-small](https://imgur.com/veYaWh7.png)
    
  #### overview.txt
  This is the main output file. It includes the options used in the most recent scan, the attacker's system/network details (IP, OS, network mask, and gateway IP), the host range that is scanned, and # of alive hosts found. The most important part comes after all this. The next section shows systems in order from most to least vulnerable based on CVEs (see next section for details). For each host the following information is given:
 
  ![github-small](https://imgur.com/6eZZf3E.png)
    
   * IPv4 address - OS (or 'No OS Found')
   * Severity: Critical, High, Medium, Low, or None (Severity #)   `// Highest CVE rank of CVEs found for that host`
   * Critical CVEs: #   `// Count of Critical CVEs`
   * High CVEs: #   `// Count of High CVEs`
   * Medium CVEs: #   `// Count of Medium CVEs`
   * Low CVEs: #   `// Count of Low CVEs`
   * None CVEs: #   `// Count of None CVEs`
   * Total CVEs: #   `// Count of all CVEs`
   * Services Found: #   `// Number of services running found by nmap`
   * Services with Ms-Modules or BF-able: #   `// Number of services that had atleast 1 exploit module returned by Metasploit or are listed as brute-forceable ports`
   * Services Exploited: #   `// Number of services exploited using Metasploit modules or bruteforce attacks.`
  
Additionally, a folder is created for each host that is found and is named accordingly. For instance host with IP =  10.0.0.9 will have a folder named 10-0-0-9. Each of these host folders contain information regarding exploits for that host. Each service/port that is scanned will have its own .csv file named **servicePORT.csv**. Therefore if a host is running http on port 8080 and on port 80, 2 files will be genereated (http8080.csv and http80.csv). Because metasploit modules are found using the service and details about that service, the 2 example http .csv files may or may not contian the same data depending on the banner found on each port. An example (http80.csv) can been seen below:

![github-small](https://imgur.com/0ZoAfs2.png)

**exploits.csv** is another file that is created for each host. This file lists every exploit module/payload combination that was executed against that host. An example can be seen below.

![github-small](https://imgur.com/vVI9Mhg.png)

**bf-servicePORT.txt** is the last file that may be found in a host's folder. This file is only populated if a successful bruteforce attempt was made against a given service/port. The file shows the which host, service, and port was attacked and valid credentials that were found. See example (bf-ftp21.txt) below.

![github-small](https://imgur.com/nmjPAhx.png)

## CVE Ranks
A full explaination for CVSS v3.0 Ratings can be found here https://nvd.nist.gov/vuln-metrics/cvss. In summary CVE severity is given as follows:

    Severity    Score Range
    None            0
    Low         0.1 - 3.9
    Medium      4.0 - 6.9
    High        7.0 - 9.9
    Critical    9.0 - 10.0

  In this script, a system's severity is the same severity as the highest CVE found. Therefore if a system has 1 critical and 35 high CVEs, then the system is listed as critical. The severity # for each host is a simple mapping where "None" = 0, ... , "Critical" = 4, and Inconclusive (no CVEs found) = -1. If two systems are the same severity, then the system with the higher count in that severity is deemed more vulnerable. In the case that these numbers are the same also, the number of CVEs at the next leading severity level are compared and so on. 

## Recognition
Special thanks to Gleahm and tukkrrr for mental support throughout this project, and allowing me to think through my script during our 4 hour long phone calls. Also thank you to my professor who supported my project and gave me ideas/feedback when needed.
