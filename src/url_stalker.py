import threading
from scapy.all import *
from scapy.layers.tls.all import * #dunno why scapy doesnt import this by default
from urllib.request import unquote

from src import packet_utilities
from src.log import log


class URL_Stalker(threading.Thread):
    def __init__(self, exit_event, timeout):
        super().__init__()
        self.exit_event = exit_event
        self.timeout=timeout
        
    def handle_packet(self, packet):
        if packet["TCP"].dport == 80:
            load = packet.load.decode("utf-8", "ignore")
            url = packet_utilities.get_host(load) + packet_utilities.get_subhost(load)
            log.urlstalker.info("http", url=url, src=packet["IP"].src)
        elif packet["TCP"].dport == 443:
            #print("httpS packet received")
            log.urlstalker.info("https", url=packet["TLS_Ext_ServerName"].servernames[0].servername.decode("utf-8","ignore"), src=packet["IP"].src)
        else:
            print("unknown packet received:")
            packet.summary()
        
    def run(self):
        log.urlstalker.info("start",timeout=self.timeout)
        
        sniff(filter="tcp and (dst port 80 or dst port 443)",
              lfilter=lambda x: (x.haslayer("Raw") and b"GET" in x["Raw"].load) or (x.haslayer("TLSClientHello")), 
              prn=self.handle_packet, store=False, stopperTimeout=3, stopper=self.exit_event.is_set, timeout=self.timeout)
              
        log.urlstalker.info("finish")
        
