# Workon motf.sniffer
# Launch MongoDB Compass server // localhost


#imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_layer('tls')
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
import sys



# filter
filter = input("[*] Enter desired filter: ")
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
        if packet.haslayer(Raw):
            b = bytes(packet[Raw].load)
            if b[0] == 0x16:
                version =  int.from_bytes(b[1:3], 'big')
                message_len = int.from_bytes(b[3:5], 'big')
                handshake_type = b[5]
                handshake_length = int.from_bytes(b[6:9], 'big')
                print("v = ", version, " len = ", message_len, " htype =", handshake_type
                , "hlen =", handshake_length)

            

                if handshake_type == 11:
                    # never happens 
                    certs_len = int.from_bytes(b[7:11], 'big')
        

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
                "DNS qname" : (DNS_qname),
                "Raw Data" : (b)
            
                } 
        # Inserting 
        rec_id1 = collection.insert_one(pkt_rec1) 



        cursor = collection.find() 
        for record in cursor: 
            print(record)  
    else:
        print ("END")
        
        
    
    

    # Printing packet details
    #print (pkt_rec1)


    
    # Sniffing Command   
    


sniff(filter=print(filter), prn=process_packet)




