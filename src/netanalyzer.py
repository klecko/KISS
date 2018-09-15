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
    def __init__(self, gateway, resolve, active, passive, passive_arps_everyone, passive_timeout=None):
        self.gateway = gateway
        self.resolve = resolve
        self.active = active
        self.passive = passive
        self.arps = passive_arps_everyone
        self.timeout = passive_timeout
        
        self.hosts = []
        
        self.stop = False
        #print("[NET] Found", len(packets[0]), "devices connected to the network.")

    
    def display_host(self, host):
        print("IP:", host[0], "\tName: ", end="")
        print(host[1]) if host[1] else print("not resolved")
    
                
    
    def is_it_a_new_ip(self, ip):
        return ip not in [detected_host[0] for detected_host in self.hosts]
    
    
    def add_host(self, ip):
        if self.is_it_a_new_ip(ip):
            name = None
            if self.resolve: 
                ptr = packet_utilities.get_domain_pointer_to_local_ip(ip)
                name = packet_utilities.nslookup(ptr, self.gateway, "PTR")
            self.hosts.append([ip, name])
            return [ip, name]
        return False
    
    
    def active_scanning(self):
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
                self.add_host(ip)
            time.sleep(1)
    
        
    def results(self):
        if self.active and self.passive:
            log.netanalyzer.info("finish", type="active", devices=len(self.hosts))
            log.netanalyzer.info("start", type="passive", timeout=self.timeout, arps=self.arps)
        
        elif self.passive: log.netanalyzer.info("start", type="passive", timeout=self.timeout, arps=self.arps)
        elif self.active: log.netanalyzer.info("finish", type="active_only", devices=len(self.hosts))
        
        for host in self.hosts:
            self.display_host(host)
            
        if self.active and not self.passive: print()
        
        
    def handle_passive_scanning(self, p):
        if p.haslayer("ARP"):
            ip = p["ARP"].psrc
        elif p.haslayer("IP"):
            ip = p["IP"].src
            
        host = self.add_host(ip)
        if host:
            self.display_host(host)


    def passive_scanning(self):
        if self.arps:
            original = verbose.arps.verbose
            verbose.arps.verbose = False
            
            e = threading.Event()
            t = arp.ARP_Spoofer(e, "everyone", self.gateway, None, 2, False)
            t.start()
            
        
        sniff(filter="arp or ip", lfilter= lambda p: (p.haslayer("IP") and p["IP"].src.startswith("192.")) or p.haslayer("ARP"),
              prn=self.handle_passive_scanning, timeout=self.timeout, store=False, stopper=lambda: self.stop, stopperTimeout=2)
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
        self.start_time = time.time()
        
        if self.active:
            try:
                self.active_scanning()
            except KeyboardInterrupt:
                pass
        self.results()
        if self.passive: 
            try:
                self.passive_scanning()
            except KeyboardInterrupt:
                self.stop = True
                

        
            



#analyze_network("192.168.191.1", True)
