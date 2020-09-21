from scapy.all import *
from datetime import * #datetime, timedelta
import os, sys, signal
from pymongo import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)


now = datetime.now()
stop = now + timedelta(seconds=120) #amount of time the script will run for. Can do minutes=x or hours=x

conn = MongoClient() 
print("Connected successfully!!!") 
filter = input("[*] Enter desired filter: ")


        # database 
db = conn.database 
collection = db.sn

class Sniffer:
    
    def process_packet(packet):
        try:
            while datetime.now() < stop:
                #TCP Syn + SynAck packet capture and DNS port 53 packet capture.
                pkts = sniff(filter=(filter), session=IPSession, # defragment on-the-flow
                count=11, prn=process_packet, lfilter=insert_db)
                
                
                #Add TCP destination packets to a temp list for follow on comparison
                for packet in pkts:
                        
                    if packet.haslayer(TCP):
                        SrcIP = packet[IP].src
                        DstIP = packet[IP].dst
                        SrcPort = packet[TCP].sport
                        DstPort = packet[TCP].dport
                        TTL = packet[IP].ttl
                        Protocol = packet[IP].proto
                
                        # DNS parsing for to record multiple DNS entries and extract/normalize PTR requests
                        ## Without this loop cnly the first DNS entry will be returned and the PTR records will be missed.
                    if packet.haslayer(UDP): # Triggers if a UDP packet
                        SrcIP = packet[IP].src
                        DstIP = packet[IP].dst
                        SrcPort = packet[TCP].sport
                        DstPort = [TCP].dport
                        TTL = packet[IP].ttl
                        Protocol = packet[IP].proto

                        
                    if packet.haslayer(IP):
                        if packet.haslayer(DNSRR): # If there is a DNS Response
                            a_count = packet[DNS].ancount 
                            #Find how many answers returned
                            i = a_count + 4
                            arp = "arpa"
                            while i > 4:
                                if str(packet[0][i].rdata)[0].isdigit():
                                    #print(packet[0][i].rdata)
                                    DNS = (packet[0][i].rdata)
                                    #Useing 'count' to see if the telltale PTR 
                                    #lookup string is in the rrname field
                                elif packet[0][i].rrname.decode().count("in-addr.arpa")>0:
                                    #print(packet[0][i].rrname.decode())
                                    base = (packet[0][i].rrname.decode())
                                    chop = base[:-14]
                                    work = chop.split('.')
                                    DNSf = work[3]+"."+work[2]+"."+work[1]+"."+work[0]
                                    print (DNSf)
                    if HTTP in packet:
                        if HTTPResponse in packet:
                            # status codes are only in responses
                            StatusCode = packet[HTTPResponse].Status_Code
                            print(StatusCode)
                    if ARP in packet:
                        if packet[ARP].op == 1: #request
                            PSrc = packet[ARP].psrc
                            PDst = packet[ARP].pdst
                        if packet[ARP].op == 2: #response
                            HwSrc = packet[ARP].hwsrc
                            PSrcc = packet[ARP].psrc             

                
        except KeyboardInterrupt:
                print('Sniffer turned off!')
            
    def insert_db():
        if TCP in filter:
            pkt_rec1= {
                "Timestamp": (now),
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "IP source": (SrcIP),
                "IP destination": (DstIP),
                "Source port": (SrcPort),
                "Destination port": (DstPort),
                "Protocol": (Protocol),
                "TTL": (TTL),
                "Status-Code": (StatusCode),
                "DNS": (DNS),
                "DNSf":(DNSf)
        }
        
        
        rec_id1 = collection.insert_one(pkt_rec1)
        
        if UDP in filter:
            pkt_rec2= {
                "Timestamp": (now),
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "IP source": (SrcIP),
                "IP destination": (DstIP),
                "Source port": (SrcPort),
                "Destination port": (DstPort),
                "Protocol": (Protocol),
                "TTL": (TTL),
                "Status-Code": (StatusCode),
                "DNS": (DNS),
                "DNSf":(DNSf)
        }
        
        
        
        rec_id2 = collection.insert_one(pkt_rec2)
        
        if ARP in filter:
            pkt_rec3= {
                "Timestamp": (now),
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "Request psrc": (PSrc),
                "Request Pdst": (PDst),
                "Response Hwsrc": (Hwsrc),
                "Reponse Psrc": (Psrcc)
        }
    
        
        rec_id3 = collection.insert_one(pkt_rec3)
        
        else:
            
            pkt_rec4= {
                "Timestamp": (now),
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "IP source": (SrcIP),
                "IP destination": (DstIP),
                "Source port": (SrcPort),
                "Destination port": (DstPort),
                "Protocol": (Protocol),
                "TTL": (TTL),
                "Status-Code": (StatusCode),
                "DNS": (DNS),
                "DNSf":(DNSf)
        }
        
        
        
        rec_id4 = collection.insert_one(pkt_rec4)
        

if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.process_packet()
