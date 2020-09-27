
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
from scapy.all import *
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
import sys


class MOTFSniffer():
    db_conn = None # Database connection handle
    db_url = None     # Database connection URL
    packet = None   # Sniffed packed that we need to process
    db_collection = None   # Name of the MongoDB Collection/Table

    def init(self, db_url=None):
        self.db_url = db_url
        self.connect_to_db()
        self.validateSniffer()
        
    def validateSniffer(self,packet):
        try: 
            sniff(prn=self.validateSniffer)
            print("Sniffer running successfully") 
        except: 
            print("Could not sniff packets") 

    def connect_to_db(self):        
        self.db_conn = MongoClient(self.db_url)
        db = self.db_conn.database
        self.db_collection = db.sn   # Or whatever your Collection is called
        
    
    def process_packet(self, packet):
        '''
        Packet is provided to the method by the sniff() function, so you can use it directly
        '''
        packet_data = {}
        def _parse_packet_ip_layer(self, packet):
            packet_data['ip_src'] = packet[IP].src
            packet_data['ip_dst'] = packet[IP].dst
            packet_data['TTL'] = packet[IP].ttl
            packet_data['Protocol'] = packet[IP].proto
            if HTTPResponse in packet:
                # status codes are only in responses
                packet_data['statuscode'] = packet[HTTPResponse].Status_Code

            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                packet_data['DNS_qname'] =(str(packet.getlayer(DNS).qd.qname))
                print (DNS_qname)
                
        def _parse_packet_tcp_layer(self,packet):
            packet_data['sport']=packet[TCP].sport
            packet_data['dport']=packet[TCP].dport
            
        def _parse_packet_udp_layer(self,packet):
            packet_data['sport']=packet[UDP].sport
            packet_data['dport']=packet[UDP].dport
            
        return packet_json
    
    def read_and_save(self, packet):
        
        if packet.haslayer(IP):
            packet_json = self._parse_packet_ip_layer(packet)
            
        if packet.haslayer(TCP):
            packet_json = self._parse_packet_tcp_layer(packet)
            
        if packet.haslayer(UDP):
            packet_json = self._parse_packet_udp_layer(packet)
            # Finally save the packet to the database
        
        collection.insert_one(packet_data)
        


    def main():
        sniff(filter=args.filter or "", count=args.count, prn=self.read_and_save)
    
    def get_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("--db_url", help="DB link", default="http://localhost:27017/")
        parser.add_argument(
            "--count",
            type=int,
            help="The number of packets to sniff (integer). 0 (default) is indefinite count.",
            default=1,
        )
        parser.add_argument("--filter", help="The BPF style filter to sniff with.")
        
        return parser.parse_args()
            
    

if __name__ == "__main__":
    # TODO: Implement click() and get the --db-url option from it into a local variable so you can use it in the next line
    args = get_args()
    motf_sniffer = MOTFSniffer(db_url=args.db_url)
    motf_sniffer.main()
