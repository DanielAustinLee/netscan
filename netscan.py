from scapy.all import *

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

    return activeHosts

   

def portScan(ipAddress, port):
    ans, uans = sr(IP(dst=host)/TCP(sport=RandShort(),dport=port,flags="S"),timeout=0.5)
    print(port + " port at host " + ipAddress)

def main():
    
    while True:
	startAddress = raw_input("Starting Address: ")
	endAddress = raw_input("Ending Address: ")
        hostList = scanAddresses(str(startAddress), str(endAddress))
	
	for address in hostList:
	    portScan(address, 8080)
main()
