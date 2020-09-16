# Workon motf.sniffer
# Launch MongoDB Compass server // localhost


#imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse



# filter
filter = input("[*] Enter desired filter: ")### DB
start = 0
# Packet capturing process
def process_packet(packet):
    
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            DNS_qname=(packet.getlayer(DNS).qd.qname)
            print (DNS_qname)
            
    if TCP in packet:
        tcp_sport=packet[TCP].sport
        tcp_dport=packet[TCP].dport
        tcp_payload= str(bytes(packet[TCP].payload))
        

    # Connecting to MongoDB    
    if start ==0:
        try: 
            conn = MongoClient() 
            print("Connected successfully!!!") 
        except: 
            print("Could not connect to MongoDB") 


        # database 
        db = conn.database 

        # Created or Switched to collection names
        collection = db.SNIFF
        
        #Document dict

        pkt_rec1 = { 
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "IP source": (ip_src),
                "IP destination": (ip_dst),
                "Source port": (tcp_sport),
                "Destination port": (tcp_dport),
                "HTTP payload": (tcp_payload),
                "DNS qname" : (DNS_qname)
            
                } 
        # Inserting 
        rec_id1 = collection.insert_one(pkt_rec1) 



        cursor = collection.find() 
        for record in cursor: 
            print(record)  
    else:
        print ("END")
        
        
    
    

    # Printing packet details
    print (pkt_rec1)


    
    # Sniffing Command   
    


sniff(iface='en0', filter=print(filter), store=0, prn=process_packet)




