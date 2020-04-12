# Purple-Pwny
Automatted Purple Team Script

## Overview
The idea behind this script is simple: Rank hosts on a given subnet and attempt to exploit them using Metasploit modules without the need of an operator. Simply put, a user with no penetration testing or vulnerability assessment experience can run this script and gain knowledge about weaknesses in the systems connected to the network. The ideal user is a red (offensive) team or blue (defensive) team member, hence the "purple" in "Purple-Pwny". "Pwn" in that name is a slang term for 'defeating' or 'to get the better of' something else, in this case another system. Pwn was morphed into Pwny for no reason other than "Purple-Pwn" just didn't seem fitting enough, and let's face it, all scripts needed a good mascot! 

## Prerequisites
The idea was to limit the number of external dependecies as much as possible, however a few non-standard libraries were used. Below is a simple guide that will allow you to install and test the script out. For the time-being, this script does not work in Windows enviroments. This is something that will be worked on as time goes on and demand calls for it.
  1. install python3
  2. `sudo pip3 install python-nmap, pymetasploit3, netifaces, pandas`
  3. `git clone https://github.com/sahullander/Purple-Pwny.git`

## Executing the script
Executing the python script is easy. Change into the directory where "purplepwny.py" exists (inside the Purple-Pwny folder if you used git to download the script). Then run `sudo python3 purplepwny.py -h` to see a list of available options detailed below.
  ```
  usage: test.py [-h] [--b B B] [--p P] 
  
  optional arguements:
  -h, --help  show this help message and exit
  --b B B     Specify filepaths for bruteforce users list [arg1] and passwords list [arg2].
  --p P       Specify number of payloads per exploit module to try.
  ```
  
  ## Example Output
  There are 4 .txt output files: IPList.txt, serviceDetails.txt, cveDetails.txt, and overview.txt. Examples for each of these can be found in the "OutputSamples" folder
   
  #### IPList.txt
  This file simply list all IPv4 addresses of alive hosts on the network.
    
  #### serviceDetails.txt
  This file provides a nmap-like output of services for each host. Information includes: host IPv4 address, ports, service name, service product, and service version.
    
  #### cveDetails.txt
  This file provides information regarding to each CVE found during the scan. Each host shows the port and associated CVEs for the service running on that port. CVE details include the CVE name, rank, and a link to read about the CVE.
    
  #### overview.txt
  This is the main output file. It includes the options used in the most recent scan, the attacker's system/network details (IP, OS, network mask, and gateway IP), the host range that is scanned, and # of alive hosts found. The most important part comes after all this. The next section shows systems in order from most to least vulnerable based on CVEs (see next section for details). For each host the following information is given:
    
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

  ## CVE Ranks
  A full explaination for CVSS v3.0 Ratings can be found here https://nvd.nist.gov/vuln-metrics/cvss. In summary CVE severity is given as follows:
    
    ```
    Severity    Score Range
    None            0
    Low         0.1 - 3.9
    Medium      4.0 - 6.9
    High        7.0 - 9.9
    Critical    9.0 - 10.0
    ```
