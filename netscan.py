from netifaces import *
import socket
import subprocess
import os
import threading
from scapy.all import *

# parameter ipAddress: IP address to scan
# returns True if host is up, False if host is down
def pingScan(ipAddress):

    try:
        subprocess.check_output("ping -c 1 " + ipAddress)

    except Exception:
        return False

    return True

#parameter addressList: list of IP addresses to scan
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

def portScan(ipAddress, port):
    pass

def main():
    print(pingScan("8.8.8.8"))
    scanAddresses("8.8.8.8", "8.8.8.255")

main()