from scapy.all import *

# parameter ipAddress: IP address to scan
# returns True if host is up, False if host is down
def pingScan(ipAddress):


    pingr = IP(dst=ipAddress)/ICMP()
    ans, unans = sr(pingr, timeout=1, verbose = False)
    print(ans)

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

                    pingScan(str(firstField) + "." + str(secondField) + "." + str(thirdField) + "." + str(fourthField))

   

def portScan(ipAddress, port):
    pass

def main():

    scanAddresses("8.8.8.8", "8.8.8.255")

main()
