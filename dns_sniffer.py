# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

filter = "tcp and port 80"


def process_packet(packet):
    breakpoint()
    print (packet)

sniff(iface='en0', filter=filter, store=0, prn=process_packet)
