
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
from scapy.all import *
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
from scapy.sessions import *
from scapy.layers import *
import sys

#filter = input("Please enter desired filter: ")
class MOTFSniffer():
    conn = None # Database connection handle
    db_url = None     # Database connection URL
    packet = None   # Sniffed packed that we need to process
    collection = None   # Name of the MongoDB Collection/Table

    def __init__(self, db_url = None):
        self.connect_to_db()
        self.validateSniffer()
        
        
    def validateSniffer(self):
        '''
        checking if sniffer is working
        '''
        try: 
            sniff(count=1)
            print("Sniffer running successfully") 
        except: 
            print("Could not sniff packets") 

    def connect_to_db(self):
        '''
        connecting to databse and accessing a collection
        '''        
        self.conn = MongoClient()
        db = self.conn.database
        print("Connected to Mongo")
        self.collection = db.test   # Or whatever your Collection is called
        print("Accessed collection")
    
    
        '''
        Packet is provided to the method by the sniff() function, so you can use it directly
        '''
        
    
            
    def parse_packet_tcp_layer(self,packet):
        print ("Parsing TCP Layer")
        packet_data = {}
        packet_data['ip_src'] = packet[IP].src
        packet_data['ip_dst'] = packet[IP].dst
        packet_data['sport']= packet[TCP].sport
        packet_data['dport']= packet[TCP].dport
        packet_data['TTL'] = packet[IP].ttl
        packet_data['Protocol'] = packet[IP].proto
        
        if HTTPResponse in packet:
            # status codes are only in responses
            packet_data['statuscode'] = packet[HTTPResponse].Status_Code
        else:
            packet_data['statuscode'] = ("None")

        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            packet_data['DNS_qname'] =(str(packet.getlayer(DNS).qd.qname))
        else:
            packet_data['DNS_qname'] = ("None")
            
        
        
        return packet_data
        
    def parse_packet_udp_layer(self,packet):
        print ("Parsing UDP Layer")
        packet_data = {}
        packet_data['ip_src'] = packet[IP].src
        packet_data['ip_dst'] = packet[IP].dst
        packet_data['sport']= packet[UDP].sport
        packet_data['dport']= packet[UDP].dport
        packet_data['TTL'] = packet[IP].ttl
        packet_data['Protocol'] = packet[IP].proto
        
        if HTTPResponse in packet:
            # status codes are only in responses
            packet_data['statuscode'] = packet[HTTPResponse].Status_Code
        else:
            packet_data['statuscode'] = ("None")

        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            packet_data['DNS_qname'] =(str(packet.getlayer(DNS).qd.qname))
        else:
            packet_data['DNS_qname'] = ("None")
        
        
        return packet_data
            
        
    
    def read_and_save(self, packet):
        ''' reading packets and inserting packet info to database collection
        '''
        
            
        if packet.haslayer(TCP):
            packet_final = self.parse_packet_tcp_layer(packet)
            
        if packet.haslayer(UDP):
            packet_final = self.parse_packet_udp_layer(packet)
            # Finally save the packet to the database
        
        self.collection.insert_one(packet_final)
        print("Packets sent to MongoDB Collection (-)")
        


    def main(self):
        ''' 
        starting the sniffing process
        '''
        sniff(filter= args.filter or "", prn= self.read_and_save, count = args.count)
        print ("Sniffed (-) packets successfuly")


def get_args():
    '''
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("--db_url", help="DB link", default="mongodb://localhost:27017/")
    parser.add_argument(
        "--count",
        type=int,
        help="The number of packets to sniff (integer). 0 (default) is indefinite count.",
        default=1,
    )
    parser.add_argument("--filter", help="The BPF style filter to sniff with.")
    
    return parser.parse_args()
            
    

if __name__ == "__main__":
    args = get_args()
    motfs = MOTFSniffer(db_url=args.db_url)
    motfs.main()
    
