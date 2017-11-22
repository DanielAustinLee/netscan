from scapy.all import *

#Suppress scapy output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# parameter ipAddress: IP address to scan
# returns True if host is up, False if host is down
def pingScan(ipAddress):

    pingr = IP(dst=ipAddress)/ICMP()
    ans, unans = sr(pingr, timeout=0.5, verbose = 0)
    
    return len(ans) == 1

#parameter startAddress: IP address to start scanning
#parameter endAddress: IP address to stop scanning

def scanAddresses(startAddress, endAddress):
    startAddress = startAddress.split(".")
    endAddress = endAddress.split(".")

    activeHosts = []

    for firstField in range(int(startAddress[0]), int(endAddress[0]) + 1):

        for secondField in range(int(startAddress[1]), int(endAddress[1]) + 1):

            for thirdField in range(int(startAddress[2]), int(endAddress[2]) + 1):

                for fourthField in range(int(startAddress[3]), int(endAddress[3]) + 1):

                    if pingScan(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField)):
			
			
			activeHosts.append(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField))

    for i in activeHosts:
	print(i + " is up.")
    return activeHosts

   
#parameter ipAddress: IP address of host to be scanned
#parameter port: Port to be scanned
def portScan(ipAddress, startPort, endPort):
    ans, uans = sr(IP(dst=ipAddress)/TCP(sport=RandShort(),dport=(startPort, endPort),flags="S"),timeout=0.5)
    
    if ans:
	print(str(port) + " port at host " + str(ipAddress) + " is up.")

def main():
    
    ans, uans = sr(IP(dst="192.168.1.74")/TCP(sport=RandShort(),dport=62078,flags="S"),timeout=0.5)
    
    print(ans)

    while True:
	startAddress = raw_input("Starting Address: ")
	endAddress = raw_input("Ending Address: ")
        hostList = scanAddresses(str(startAddress), str(endAddress))
	
	for address in hostList:
	    print(str(address))
	    portScan(address, 1000, 8000)
main()
