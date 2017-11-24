from scapy.all import *

#Suppress scapy output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


load_module("p0f")


# parameter ipAddress: IP address to scan
# returns True if host is up, False if host is down
def pingScan(ipAddress):

    try:
        pingr = IP(dst=ipAddress)/ICMP()
        ans, _ = sr(pingr, timeout=0.5, verbose = 0)

    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return len(ans) == 1

#parameter startAddress: IP address to start scanning
#parameter endAddress: IP address to stop scanning
#returns a list of active hosts
def scanAddresses(startAddress, endAddress):
    startAddress = startAddress.split(".")
    endAddress = endAddress.split(".")

    activeHosts = []

    try:

        for firstField in range(int(startAddress[0]), int(endAddress[0]) + 1):

            for secondField in range(int(startAddress[1]), int(endAddress[1]) + 1):

                for thirdField in range(int(startAddress[2]), int(endAddress[2]) + 1):

                    for fourthField in range(int(startAddress[3]), int(endAddress[3]) + 1):

                        if pingScan(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField)):


        			activeHosts.append(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField))


    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return activeHosts

   
#parameter ipAddress: IP address of host to be scanned
#parameter port: Port to be scanned
def portScan(ipAddress, startPort, endPort):
    openPorts = []

    try:

        for port in range(startPort, endPort + 1):
            ans, uans = sr(IP(dst=ipAddress)/TCP(sport=RandShort(),dport=port,flags="S"),timeout=0.5)

            if len(ans) > 0:
                openPorts.append(port)
	        detectOS()

    except KeyboardInterrupt:
	raise KeyboardInterrupt()

    return openPorts

#Parameter portDictionary: Dictionary where keys are ip addresses and values are lists containing open ports for that key
#Returns a string containing a report of the portDictionary
def makeReport(portDictionary):

    report = ""
    
    for address in portDictionary.keys():

	report = report + "\nOpen ports on " + str(address)

	for port in portDictionary[address]:

	    report = report + "\n" + str(port)

    return report


#os fingerprint stub
def detectOS():
    pass


def main():
    
    addressDict = {}
    
    try:

        while True:
            startAddress = raw_input("Starting Address: ")
	    endAddress = raw_input("Ending Address: ")
            hostList = scanAddresses(str(startAddress), str(endAddress))
	
	    for x in hostList:
		
	        addressDict[x] = []


	    for address in addressDict.keys(): 
	        addressDict[address] = portScan(address, 1, 200)

	    print(makeReport(addressDict))

    except KeyboardInterrupt:
	print("\n\nGoodbye\n\n")

    except ValueError:
	print("Invalid Address")
	main()

main()

