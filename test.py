"""
Prerequisites

* Install the necessary modules as follows

    mkvirtualenv --python /usr/local/bin/python3.8 sniffer
    workon sniffer
    pip install -r requirements.txt

The run the application
    
    python test.py

"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pymongo
from scapy.all import sniff
import scapy_http.http
from scapy.layers.http import HTTPRequest



start = 0

def process_packet(packet):
    """
    Process each packet individually
    """

    http_packet = packet.getlayer(scapy_http.http.HTTPRequest)

    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
    if TCP in packet:
        tcp_sport=packet[TCP].sport
        tcp_dport=packet[TCP].dport
        
    # Look at the following methods to get some more detail:
    # http_packet.display
    # http_packet.show()
    # http_packet.fields - provides a dictionary of fields

    # I'm not clear what you're trying to do here. Maybe you mean ..
    # if (http_packet.fields.get("Method") == "GET"): ...?
    if http_packet.find('GET'):
            return GET_print(packet)
        
    if start ==0:
        try: 
            conn = MongoClient() 
            print("Connected successfully!!!") 
        except: 
            print("Could not connect to MongoDB") 


        # database 
        db = conn.database 

        # Created or Switched to collection names: my_gfg_collection 
        collection = db.SNIFF
        
        

        pkt_rec1 = { 
                "MAC addr source":(packet.src), 
                "MAC addr destination":(packet.dst), 
                "interface": (packet.sniffed_on),
                "IP source": (ip_src),
                "IP destination": (ip_dst),
                "Source port": (tcp_sport),
                "Destination port": (tcp_dport),
                "HTTP content": (ret)
                } 

        rec_id1 = collection.insert_one(pkt_rec1) 



        cursor = collection.find() 
        for record in cursor: 
            print(record)  
    else:
        print ("END")
        
        
    
    
    #breakpoint()
    print (packet)
    print (packet.name)
    print (packet.src)
    print (packet.dst)
    print (packet.sniffed_on)
    print (ip_src)
    print (ip_dst)
    print (tcp_sport)
    print (tcp_dport) 
    print (packet1)
    
    # Sniffing Command   
    
def GET_print(packet1):
    """
    Good to add what this function is for, and the parameters
    """
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

if __name__ == "__main__":
    interface = "en0"   # bind to the first wireless interface
    pkt_filter = "ip and tcp and port 80"

    sniff(iface='en0', filter=pkt_filter, 
          lfilter=lambda x: x.haslayer(scapy_http.http.HTTPRequest),
          store=0, 
          prn=process_packet)


