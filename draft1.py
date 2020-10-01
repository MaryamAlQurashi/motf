import argparse
import logging
from datetime import * 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
from scapy.all import *
from pymongo import *
load_layer("http")
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
from scapy.sessions import *
from scapy.layers import *
import sys

now = datetime.now()

class MOTFSniffer():
    conn = None # Database connection handle
    db_url = None     # Database connection URL
    packet = None   # Sniffed packed that we need to process
    collection = None   # Name of the MongoDB Collection/Table
    packet_count = None
    filter = None
    #interface = None

    def __init__(self, db_url = None, filter=None, count=None, interface=None):
        self.connect_to_db()
        self.validateSniffer()
        self.filter = filter
        self.packet_count = count
        #self.interface = interface
        
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
        connecting to database and accessing a collection
        '''        
        self.conn = MongoClient()
        db = self.conn.database
        print("Connected to Mongo")
        self.collection = db.testhttplayer   # Or whatever your Collection is called
        print("Accessed collection")
    
    
        '''
        Packet is provided to the method by the sniff() function, so you can use it directly
        '''
        
    
            
    def parse_packet_tcp_layer(self,packet):
        print ("Parsing TCP Layer")
        packet_data = {
            'TIME': now,
            'IP_SRC': packet[IP].src if packet.haslayer(IP) else None,
            'IP_DST': packet[IP].dst if packet.haslayer(IP) else None,
            'SRC_PORT': packet[TCP].sport,
            'DST_PORT': packet[TCP].dport,
            'TTL': packet[IP].ttl if packet.haslayer(IP) else None,
            'PROTOCOL': packet[IP].proto if packet.haslayer(IP) else None,
            'HTTP_V': str(packet[HTTPResponse].Http_Version) if packet.haslayer(HTTPResponse) else None,
            'STATUS_CODE': str(packet[HTTPResponse].Status_Code) if packet.haslayer(HTTPResponse) else None,
            'REASON_PH': str(packet[HTTPResponse].Reason_Phrase) if packet.haslayer(HTTPResponse) else None,
            'CONT-LEN': str(packet[HTTPResponse].Content_Length) if packet.haslayer(HTTPResponse) else None,
            'CONT-TYPE': str(packet[HTTPResponse].Content_Type) if packet.haslayer(HTTPResponse)  else None,
            'URL': packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode() if packet.haslayer(HTTPRequest) else None,
            'METHOD': packet[HTTPRequest].Method.decode() if packet.haslayer(HTTPRequest) else None
        }
        
        
        return packet_data
        
    def parse_packet_udp_layer(self,packet):
        print ("Parsing UDP Layer")
        packet_data = {
            'TIME': now,
            'IP_SRC': packet[IP].src if packet.haslayer(IP) else None,
            'IP_DST': packet[IP].dst if packet.haslayer(IP) else None,
            'SRC_PORT': packet[UDP].sport,
            'DST_PORT': packet[UDP].dport,
            'TTL': packet[IP].ttl if packet.haslayer(IP) else None,
            'PROTOCOL': packet[IP].proto if packet.haslayer(IP) else None,
            'HTTP_V': str(packet[HTTPResponse].Http_Version) if packet.haslayer(HTTPResponse)  else None,
            'STATUS_CODE': str(packet[HTTPResponse].Status_Code) if packet.haslayer(HTTPResponse) else None,
            'REASON_PH': str(packet[HTTPResponse].Reason_Phrase) if packet.haslayer(HTTPResponse) else None,
            'CONT-LEN': str(packet[HTTPResponse].Content_Length) if packet.haslayer(HTTPResponse) else None,
            'CONT-TYPE': str(packet[HTTPResponse].Content_Type) if packet.haslayer(HTTPResponse)  else None,            
            'URL': packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode() if packet.haslayer(HTTPRequest) else None,
            'METHOD': packet[HTTPRequest].Method.decode() if packet.haslayer(HTTPRequest) else None
        }


        
        
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
        # sniff(filter= self.filter, prn= self.read_and_save, count=self.packet_count)
        sniff(
            filter=self.filter,
            #iface=self.interface, 
            prn=self.read_and_save,
            count=self.packet_count
        )
        print ("Sniffed (-) packets successfuly")


def get_args():
    '''
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("--db_url", help="DB link", default="mongodb://localhost:27017/")
    #parser.add_argument("--interface", help="Interface to sniff on, such as en0", required=True)
    parser.add_argument(
        "--count",
        type=int,
        help="The number of packets to sniff (integer). 0 (default) is indefinite count.",
        default=5,
    )
    parser.add_argument("--filter", help="The BPF style filter to sniff with. Eg. 'tcp port 80'", required=True)
    
    return parser.parse_args()
            
    

if __name__ == "__main__":
    args = get_args()
    motfs = MOTFSniffer(db_url=args.db_url, filter=args.filter, count=args.count) #interface=args.interface)
    motfs.main()
