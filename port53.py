
from scapy.all import *
import sys


def dns_sniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			print (pkt.getlayer(DNS).qd.qname)
			print (pkt.summary)

                
sniff(iface = "en0" ,filter = "port 53", prn = dns_sniff, store = 0)
