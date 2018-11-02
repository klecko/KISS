#Ver por que peta en mi otro pc:
#dst = "192.168.191.1/25" funciona, pero /24 peta.
#si hago el /25 dos veces seguidas tambien peta

import time
import threading
from scapy.all import *

from src import arp
from src import packet_utilities
from src.log import log, verbose


class Network_Analyzer():
    """Class of the Network Analyzer module. Note that this is not a Thread.
    
    Performs active and passive scanning of the network in order to detect
    devices.
    """
    
    def __init__(self, gateway, resolve, active, passive, passive_arps_everyone, passive_timeout=None):
        """Creates the thread.
        
        Parameters:
            gateway (str): the IP address of the gateway.
            resolve (bool): if True, each IP Address will be resolved to
                guess the name of the device.
            active (bool): if True, an active scanning will be performed.
            passive (bool): if True, a passive scanning will be performed.
            passive_arps_everyone (bool): if True, an ARP Spoofing attack will
                be performed to the whole net in order to detect devices. 
                Warning: this makes passive scanning noisier.
            passive_timeout (int, None): the time in seconds of the duration of
                the passive scanning. If None, it will last until CTRL-C is 
                pressed. It is set to None by default.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        
        self.gateway = gateway
        self.resolve = resolve
        self.active = active
        self.passive = passive
        self.arps = passive_arps_everyone
        self.timeout = passive_timeout
        
        self.hosts = []
        
        self.stop = False
        #print("[NET] Found", len(packets[0]), "devices connected to the network.")

    
    def _display_host(self, host):
        """Displays a host.
        
        Parameters:
            host (tuple): tuple whose first element is the IP and the second
                element is the name, which can be None.
        """
        
        print("IP:", host[0], "\tName: ", end="")
        print(host[1]) if host[1] else print("not resolved")
    
                
    
    def _is_it_a_new_ip(self, ip):
        """Checks if the given IP has not been detected yet.
        
        Parameters:
            ip (str): the possible new IP address.
            
        Returns:
            bool: True if it is a new IP, False otherwise.
        """
        
        return ip not in [detected_host[0] for detected_host in self.hosts]
    
    
    def _add_host(self, ip):
        """If the given IP is a new IP, it is added to the detected hosts list
        and resolved if desired.
        
        Parameters:
            ip (str): the detected IP address, which can be new or not.
            
        Returns:
            tuple: if the IP address hasn't been discovered yet, it returns a
                tuple containing the ip address and the name of the device
                if it was added.
            bool: False if it was not a new IP.
        """
        
        if self._is_it_a_new_ip(ip):
            name = None
            if self.resolve: 
                ptr = packet_utilities.get_domain_pointer_to_local_ip(ip)
                name = packet_utilities.nslookup(ptr, self.gateway, "PTR")
            self.hosts.append((ip, name))
            return (ip, name)
        return False
    
    
    def _active_scanning(self):
        """Performs an active network scanning."""
        
        #packets are sent to broadcast on layer 2
        #the other option was using layer 3, but you would have to wait for scapy
        #to guess the mac address of each ip. most of them do not exist, so it would end up
        #using broadcast. using broadcast directly is the best option.
        
        #note: before this was done with icmp ping requests, but arping is more effective.
        
        log.netanalyzer.info("start", type="active")
        p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway + "/24")
        
        for i in range(2):
            packets = srp(p, timeout=2, verbose=0)

            for send_and_recv in packets[0]:
                recv = send_and_recv[1]
                ip = recv["ARP"].psrc
                self._add_host(ip)
            time.sleep(1)
    
        
    def _results(self):
        """Displays the results of the active scan and other logs."""
        
        if self.active and self.passive:
            log.netanalyzer.info("finish", type="active", devices=len(self.hosts))
            log.netanalyzer.info("start", type="passive", timeout=self.timeout, arps=self.arps)
        
        elif self.passive: log.netanalyzer.info("start", type="passive", timeout=self.timeout, arps=self.arps)
        elif self.active: log.netanalyzer.info("finish", type="active_only", devices=len(self.hosts))
        
        for host in self.hosts:
            self._display_host(host)
            
        if self.active and not self.passive: print()
        
        
    def _handle__passive_scanning(self, p):
        """Handles every packet received from passive scanning. If it comes
        from an undiscovered device, it displays it.
        
        Parameters:
            packet (scapy.packet.Packet): handled packet.
        """
        
        if p.haslayer("ARP"):
            ip = p["ARP"].psrc
        elif p.haslayer("IP"):
            ip = p["IP"].src
            
        host = self._add_host(ip)
        if host:
            self._display_host(host)


    def _passive_scanning(self):
        """Performs a passive network scanning."""
        
        if self.arps:
            original = verbose.arps.verbose
            verbose.arps.verbose = False
            
            e = threading.Event()
            t = arp.ARP_Spoofer(e, "everyone", self.gateway, None, 2, False)
            t.start()
            
        
        sniff(filter="arp or ip", lfilter= lambda p: (p.haslayer("IP") and p["IP"].src.startswith("192.")) or p.haslayer("ARP"),
              prn=self._handle__passive_scanning, timeout=self.timeout, store=False, stopper=lambda: self.stop, stopperTimeout=2)
        if self.arps: 
            e.set()
            try:
                t.join()
            except KeyboardInterrupt:
                pass
            verbose.arps.verbose = original
        
        print()
        log.netanalyzer.info("finish", type="passive", time=round(time.time()-self.start_time,2), devices=len(self.hosts))


    def start(self):
        """Performs the network scanning."""
        
        self.start_time = time.time()
        
        if self.active:
            try:
                self._active_scanning()
            except KeyboardInterrupt:
                pass
        self._results()
        if self.passive: 
            try:
                self._passive_scanning()
            except KeyboardInterrupt:
                self.stop = True
