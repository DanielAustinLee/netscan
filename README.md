# netscan+
Network host and port scanner

You must have the Python module "scapy" installed to run this tool

To run, type "sudo python netscan.py" followed by available options and parameters

	OPTIONS			DESCRIPTION

	-r [startIP-endIP]      If present, will scan from given start address to the end address (make sure the "-" is between them!)	
				(if this option is not present, the tool will exit without scanning anything)

	-p [startPort-endPort]  If present, the tool will TCP port scan every identified host from the start port to the end port
				If not present, the tool will TCP port scan a list of commonly used ports that is provided in the "Common Ports" text file

	-t			If present, the tool will conduct a TCP scan of port 443 instead of a ping scan for host discovery

	
