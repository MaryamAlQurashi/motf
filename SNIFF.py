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
filter = "ip and tcp and port 80"
### DB
start = 0
# Packet capturing process
def process_packet(packet):
    
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
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
                "HTTP payload": (tcp_payload)
            
                } 
        # Inserting 
        rec_id1 = collection.insert_one(pkt_rec1) 



        cursor = collection.find() 
        for record in cursor: 
            print(record)  
    else:
        print ("END")
        
        
    
    

    # Printing packet details
    print (packet.name)
    print (packet.src)
    print (packet.dst)
    print (packet.sniffed_on)
    print (ip_src)
    print (ip_dst)
    print (tcp_sport)
    print (tcp_dport) 
    print (tcp_payload)


    
    # Sniffing Command   
    


sniff(iface='en0', filter=filter, store=0, prn=process_packet)




