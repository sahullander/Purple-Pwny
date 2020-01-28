import nmap
import socket
import struct
import os
import ipaddress
import random, string
from ftplib import FTP
from datetime import datetime
import netifaces
import platform

startTime = datetime.now()

# Generates a text-file with a random name
# Open file for writing our output and create if its not created already - random name will make it always create
rand_file = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randrange(5,9))) + ".txt"
f = open(rand_file,"a+")

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
      if netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'].startswith("192"):
         f.write("Operating System: {0} \n".format(platform.system()))
         netmask = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['netmask']
         f.write("Network Mask: {0} \n".format(netmask))
         f.write("Gateway IP: {0} \n".format(netifaces.gateways()['default'][netifaces.AF_INET][0]))
         break
      else:
         pass
   except:pass

# Creates an ipaddress object that is used to hold all of the IPs on the subnet
subnet = ipaddress.ip_network(u'{0}/{1}'.format(IP, netmask),strict=False)

print(subnet)
# Just a prompt for the output file
f.write('\nInitiating quick scan from host {0} to {1} \n'.format(subnet[0], subnet[-1]))

######## NMAP STUFF ########
nm.scan(hosts=str(subnet), arguments='-sV --version-light')
try:
	OS = nm['192.168.1.7']['osmatch']
	f.write(OS)
except:
	print("error in osmatch")
	pass

f.write("Port    Service                  Details \n")
services = [str(item).ljust(8," ") + nm['192.168.1.7']['tcp'][item]['name'].ljust(25, " ") + nm['192.168.1.7']['tcp'][item]['product'] + " " + nm['192.168.1.7']['tcp'][item]['version'] for item in nm['192.168.1.7']['tcp'].keys()]
print('\n'.join(map(str, services)))
f.write('\n'.join(map(str, services)))

"""
print(nm['192.168.1.1']['addresses']['mac'])
## gets OS possibilities (a list of dictionaries) ##
##### it looks like the first dictionary returned has the highest #####
##### 'accuracy' value however example I ran the first one was wrong... #####
nm['192.168.1.7']['osmatch']
## prints all details for a particular OS name including accuracy etc
next(item for item in nm['192.168.1.7']['osmatch'] if item['name'] == 'Microsoft Windows 10 1607')
## prints value associated with key (here its 'name') for a paricular OS name
next(item['name'] for item in nm['192.168.1.7']['osmatch'] if item['name'] == 'Microsoft Windows 10 1607')
# get all open ports
nm['192.168.1.7']['tcp'].keys()
# save and then print all services on different lines
services = [nm['192.168.1.7']['tcp'][item]['name'] for item in nm['192.168.1.7']['tcp'].keys()]
print('\n'.join(map(str, services)))
# get service running on port
nm['192.168.1.7']['tcp'][135]['name']
# get version of service of applicable
nm['192.168.1.7']['tcp'][135]['product'] + nm['192.168.1.7']['tcp'][135]['version']
# prints all services
print([nm['192.168.1.7']['tcp'][item]['name'] for item in nm['192.168.1.7']['tcp'].keys()])
"""

endTime = datetime.now()
runtime = endTime-startTime
f.write('\n\n End Script @ {0}    ---   Total Runtime: {1}'.format(endTime, runtime))
f.close()
