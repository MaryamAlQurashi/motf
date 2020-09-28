import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
from scapy.all import *
from pymongo import *
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
import sys

#filter = input("Please enter desired filter: ")
class MOTFSniffer():
    conn = None # Database connection handle
    db_url = None     # Database connection URL
    packet = None   # Sniffed packed that we need to process
    collection = None   # Name of the MongoDB Collection/Table

    def __init__(self, db_url=None):
        self.db_url = db_url
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
        self.collection = db.sn   # Or whatever your Collection is called
        print("Accessed collection")
    
    
        '''
        Packet is provided to the method by the sniff() function, so you can use it directly
        '''
        
    def parse_packet_ip_layer(self, packet):
        print ("Parsing IP Layer")
        packet_data = {}
        packet_data['ip_src'] = packet[IP].src
        packet_data['ip_dst'] = packet[IP].dst
        packet_data['TTL'] = packet[IP].ttl
        packet_data['Protocol'] = packet[IP].proto
        if HTTPResponse in packet:
            # status codes are only in responses
            packet_data['statuscode'] = packet[HTTPResponse].Status_Code

        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            packet_data['DNS_qname'] =(str(packet.getlayer(DNS).qd.qname))
            
        
        return packet_data
            
    def parse_packet_tcp_layer(self,packet):
        print ("Parsing TCP Layer")
        packet_data = {}
        packet_data['sport']=packet[TCP].sport
        packet_data['dport']=packet[TCP].dport
        return packet_data
        
    def parse_packet_udp_layer(self,packet):
        print ("Parsing UDP Layer")
        packet_data = {}
        packet_data['sport']=packet[UDP].sport
        packet_data['dport']=packet[UDP].dport
        return packet_data
            
        
    
    def read_and_save(self, packet):
        ''' reading packets and inserting packet info to database collection
        '''
        
        if packet.haslayer(IP):
            packet_final = self.parse_packet_ip_layer(packet)
            
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
        sniff(filter="ip and tcp and port 80", prn=self.read_and_save, count = 3)
        print ("Sniffed (-) packets successfuly")

            
    

if __name__ == "__main__":
    motfs = MOTFSniffer()
    motfs.main()
    
