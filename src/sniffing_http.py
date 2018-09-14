
import threading
from scapy.all import *
from urllib.request import unquote

from src import files, packet_utilities
from src.log import log, verbose


class HTTP_Sniffer(threading.Thread):
    #Sniffs every HTTP Post packet, looking for interesting information.
    
    def __init__(self, exit_event, attributes, timeout):
        super().__init__()
        self.exit_event = exit_event
        self.timeout = timeout
        if attributes == "*" or attributes == "":
            self.relevant_attributes = "*"
        else:
            self.relevant_attributes = files.get_relevant_attributes_from_file(attributes)
            
        self.packets_ids = []

        
        
    def results(self, packets):
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
            
    def handle_packet(self, packet):
        log.sniff.info("packet_found", host=packet_utilities.get_host(packet["Raw"].load.decode('utf-8', "ignore")), src=packet["IP"].src)
        self.packets_ids.append([packet.ack, packet.seq])
        
    def run(self):        
        #SNIFF, al tener stopperTimeout y stopper, no es la funcion original de Scapy, sino una modificada por mi
        #ya que la original no tenía manera de pararse cuando se quisiera. más informacion en sendrecv de Scapy
        #lo malo de esto es que para de sniffear cada stopperTimeout segundos para comprobar si stopper devuelve True,
        #con lo que puede perder algun paquete en ese proceso (cuando escribo esto aun no se ha dado el caso)
        
        #Es necesario el uso de self.packets_ids, ya que cuando se usa ARPSpoofer, se sniffea tanto
        #cuando llega un paquete como cuando se le hace forward. por ello se usa packets_ids para no repetir paquetes.
        
        log.sniff.info("start", timeout=self.timeout)
        
        try:
            packets = sniff(timeout=self.timeout, filter="tcp and dst port 80", \
                            lfilter=lambda x: x.haslayer("Raw") and b"POST" in x["Raw"].load and not [x.ack, x.seq] in self.packets_ids, \
                            prn= self.handle_packet, \
                            stopperTimeout=3, stopper=self.exit_event.is_set)
        except PermissionError as err:
            log.sniff.error("permission_sniffing", err=err)
        self.results(packets)
        
    


    


