# ==========================================LIBRARIES======================================== #

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from datetime import * 
from pymongo import *
from scapy.layers.http import *
load_layer("http")
import sys
from scapy.sessions import *



now = datetime.now()
filter = input("[*] Enter desired filter: ")
start = 0

# ===========================================DB CLASS=========================================== #

class Sniffer:

    def connecttoDB(self):
        global conn
        
        if start ==0:
            try: 
                conn = MongoClient() 
                print("Connected successfully!!!") 
            except: 
                print("Could not connect to MongoDB") 


            # database 
            db = conn.database 

            # Created or Switched to collection names
            collection = db.httpresponse
            
    def insertDB(self):
        global conn, packet
        self.connecttoDB()
        
        pkt_rec1 = { 
                    "Time": (now),
                    "interface": (packet.sniffed_on),
                    "IP source": (ip_src),
                    "IP destination": (ip_dst),
                    "Source port": (sport),
                    "Destination port": (dport),
                    "Protocol" : (Protocol),
                    "TTL" : (TTL),
                    "DNS QR" : (DNS_qname),
                    "Status Code" : (statuscode)
                    #"App Protocol" : (app_pr)
                
                    }
        
        rec_id1 = collection.insert_one(pkt_rec1)
        rec_id1
        
    
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            TTL = packet[IP].ttl
            Protocol = packet[IP].proto
            if HTTPResponse in packet:
                # status codes are only in responses
                statuscode = packet[HTTPResponse].Status_Code
            else:
                statuscode = ("None")

            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    DNS_qname=(str(packet.getlayer(DNS).qd.qname))
                    print (DNS_qname)
            else:
                DNS_qname= ("None")
        
            #if packet.haslayer(ARP):
                #app_pr = "ARP"
            #if packet.haslayer(ICMP):
                #app_pr = "ICMP"
            #else:
                #app_pr = "Error"
                
                        
        if packet.haslayer(TCP):
            sport=packet[TCP].sport
            dport=packet[TCP].dport
            
        elif packet.haslayer(UDP):
            sport=packet[UDP].sport
            dport=packet[UDP].dport
            
            
    
    
    
    def main(self):
        global conn, packet
        process_packet = self.process_packet()
        self.connecttoDB()
        sniff(filter=(filter), prn=process_packet)
        self.insertDB()
        



# =======================================INITIALIZATION======================================= #


if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.main()
