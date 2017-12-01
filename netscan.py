from scapy.all import *
import socket
import sys


#Suppress scapy output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# parameter ipAddress: IP address to scan
#returns True if host is identified as up, False if host is identified as down
def pingScan(ipAddress):

    try:
        pingr = IP(dst=ipAddress)/ICMP()
        ans, _ = sr(pingr, timeout=0.5, verbose = 0)

    except KeyboardInterrupt:
        raise KeyboardInterrupt()

    return len(ans) > 0


#parameter ipAddress: IP address to scan
#returns True if host is identified as up, False if host is identified as down
def tcpScan(ipAddress):

    try:
	tcpr = IP(dst=ipAddress)/TCP(dport=443, sport=RandShort(), flags="S")
	ans, _ = sr(tcpr, timeout=0.5, verbose = 0)
	ans[0][1].sprintf("%TCP.flags%")

    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return len(ans) > 0

#parameter startAddress: IP address to start scanning
#parameter endAddress: IP address to stop scanning
#parameter tcpScan: Flag for ping vs tcp scan
#returns a list of active hosts
def scanAddresses(startAddress, endAddress, tcpScan):
    startAddress = startAddress.split(".")
    endAddress = endAddress.split(".")

    activeHosts = []

    try:
	#If tcpScan == False, use pingScan, else use tcpScan
	if not tcpScan:
            for firstField in range(int(startAddress[0]), int(endAddress[0]) + 1):

                for secondField in range(int(startAddress[1]), int(endAddress[1]) + 1):

                    for thirdField in range(int(startAddress[2]), int(endAddress[2]) + 1):

                        for fourthField in range(int(startAddress[3]), int(endAddress[3]) + 1):

                            if pingScan(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField)):

        		        activeHosts.append(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField))
	else:

            for firstField in range(int(startAddress[0]), int(endAddress[0]) + 1):

                for secondField in range(int(startAddress[1]), int(endAddress[1]) + 1):

                    for thirdField in range(int(startAddress[2]), int(endAddress[2]) + 1):

                        for fourthField in range(int(startAddress[3]), int(endAddress[3]) + 1):

                            if tcpScan(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField)):

        		        activeHosts.append(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField))

    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return activeHosts


#parameter ipAddress: IP address of host to be scanned
#parameter portList: List of ports to be scanned
#Returns a list of ports determined to be open
def portScan(ipAddress, portList = None):
    openPorts = []


    try:
	#For every port in range send TCP SYN packet and get response
        for port in portList:
            ans, uans = sr(IP(dst=ipAddress)/TCP(sport=RandShort(),dport=port,flags="S"),timeout=0.5)

	    #If there is a response, log port as open
            if len(ans) > 0:
                openPorts.append(port)

    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return openPorts

#Parameter portDictionary: Dictionary where keys are ip addresses and values are lists containing open ports for that key
#Returns a string containing a report of the portDictionary
def makeReport(portDictionary):

    report = ""

    #For every entry in dict, list IP address and enumerate open ports
    for address in portDictionary.keys():

        report = report + "\nOpen ports on " + str(address) 

	try:
	    report = report + " (" + socket.gethostbyaddr(address)[0] + ")"

	except socket.herror:
	    report = report + " (unknown host name)"

	report = report + "\nOperating System: " + str(portDictionary[address][0])

	for port in portDictionary[address][1:]:

	    report = report + "\n" + str(port)

    return report


#Parameter ipAddress: The IP address of the host to fingerprint, in string form
#Returns a string indicating hosts operating system
def detectOS(ipAddress):

    #Create and send ICMP packet and get response
    pkt = sr1(IP(dst=ipAddress)/ICMP(), timeout = 1)

    if not pkt is None:
        if IP in pkt:

	    #Linux will make IP packets with ttl = 64
	    #Windows will make IP packets with ttl = 128
	    if pkt.getlayer(IP).ttl <= 64:
	        return "Linux/Unix"

	    else:
	        return "Windows"


def main():

    #Initialize variables
    tcpScan = False
    addressDict = {}
    startAddress = None
    endAddress = None
    portList = []

    #if -t flag is present, use tcpScan
    if "-t" in sys.argv:
	tcpScan = True

    #get ip range
    if "-r" in sys.argv:
	range = sys.argv[ 1 + sys.argv.index("-r") ]
	startAddress = range.split("-")[0]
	endAddress = range.split("-")[1]

    else:
	print("No address range specified")
	return

    #get port range
    if "-p" in sys.argv:
	range = sys.argv[ 1 + sys.argv.index("-p") ]
	startPort = range.split("-")[0]
	endPort = range.split("-")[1]

	for port in range(startPort, endPort + 1):
	    portList.append(port)

    #if not port range specified, use list of common ports
    else:
	portFile = open("Common ports", "r")
	for line in portFile.readlines():
	    if line != "\n":
	        portList.append(int(line))



    try:
	print("Starting scan")
	#hostList is a list of active hosts
        hostList = scanAddresses(str(startAddress), str(endAddress), tcpScan)

	#Adding ip addresses as keys in addressDict
        for x in hostList:

            addressDict[x] = []

	#for every key in the dictionary, os is fingerprinted and open ports added
        for address in addressDict.keys():
            addressDict[address].append(detectOS(address))
	    addressDict[address] = addressDict[address] + portScan(address, portList)

	print(makeReport(addressDict))

    except KeyboardInterrupt:
	print("\n\nGoodbye\n\n")

    except ValueError:
	print("Invalid Address")


main()

