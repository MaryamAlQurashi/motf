import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
from scapy.all import *
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
import sys

filter = input("[*] Enter desired filter: ")


class Sniffer:
        try: 
            conn = MongoClient() 
            print("Connected successfully!!!") 
        except: 
            print("Could not connect to MongoDB") 


        # database 
        db = conn.database 

        # Created or Switched to collection names
        collection = db.SNIFF
        
    def add_to_db():
        """
        Adds data to mongo db
        :param p_src: source ip address
        :param p_dest: destination ip address
        :return:
        """
        pkt_rec1= {
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
        
        rec_id1 = collection.insert_one(pkt_rec1)
            
    def process_packet(packet):
    
        if IP in packet:
            ip_src=packet[IP].src
            ip_dst=packet[IP].dst
            #print(packet.summary)
            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                DNS_qname=(packet.getlayer(DNS).qd.qname)
                print (DNS_qname)
                #print(packet.summary)

        if TCP in packet:
            tcp_sport=packet[TCP].sport
            tcp_dport=packet[TCP].dport
            tcp_payload= str(bytes(packet[TCP].payload))
            #print(packet.summary)
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

    

    sniff(filter=print(filter), prn=process_packet)




if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.process_packet()
    sniffer.add_to_db()
