#KleSniffer by KleSoft
#12/09/18


#TIMELIMIT DNS
#HACER UN ARCHIVO DE FUNCIONES COMPARTIDAS DE PAQUETES COMO GETHOST?
#MEJORAR CHECK_ARGS?
#URL STALKER RESOLVE?

#ME QUEDE CON LAS IPTABLES PARA BLOQUEAR POST Y GET

import threading
import os
import sys
import configparser
from scapy.all import *



from src import arp
from src import dns
from src import files
from src import sniffing_http
from src import js
from src import netanalyzer
from src import url_stalker
from src.log import log, colors


if platform == "linux": N_THREADS = 1
else: N_THREADS = 2 #in windows scapy runs a powershell in another thread

class Args(): #Uso esta opción en lugar de una clase sin inicializar para no tener cosas globales
    def __init__(self, file_loc):
        log.info("CONFIG", "Reading config file...")
        try:
            args = configparser.ConfigParser()
            args.read(file_loc)
            
            #NETANALYZER
            self.N_ENABLED = args.getboolean("netanalyzer", "enabled", fallback="D34D")
            self.N_GATEWAY = args.get("netanalyzer", "gateway", fallback="D34D")
            self.N_RESOLVE = args.getboolean("netanalyzer", "resolve", fallback="D34D")
            self.N_ACTIVE = args.getboolean("netanalyzer", "active", fallback="D34D")
            self.N_PASSIVE = args.getboolean("netanalyzer", "passive", fallback="D34D")
            self.N_PASSIVE_ARPS_EVERYONE = args.getboolean("netanalyzer", "passive_arps_everyone", fallback="D34D")
            self.N_PASSIVE_TIMEOUT = args.getint("netanalyzer", "passive_timeout", fallback="D34D")
            
            #SNIFF
            self.S_ENABLED = args.getboolean("sniff", "enabled", fallback="D34D")
            self.S_TIME_SECS = args.get("sniff", "time_limit", fallback="D34D")
            self.S_ATTRIBUTES = args.get("sniff", "attributes", fallback="D34D")
            self.S_TIME_SECS = int(self.S_TIME_SECS) if not self.S_TIME_SECS == '' else None
        
            #ARPS
            self.A_ENABLED = args.getboolean("arps", "enabled", fallback="D34D")
            self.A_TARGET_IP = args.get("arps", "target", fallback="D34D").lower()
            self.A_GATEWAY_IP = args.get("arps", "gateway", fallback="D34D")
            self.A_TIME_SECS = args.get("arps", "time_limit", fallback="D34D")
            self.A_INTERVAL = args.getint("arps", "interval", fallback="D34D")
            self.A_DISCONNECT = args.getboolean("arps", "disconnect", fallback="D34D")
            self.A_TIME_SECS = int(self.A_TIME_SECS) if not self.A_TIME_SECS == '' else None

            #DNS
            self.D_ENABLED = args.getboolean("dns", "enabled", fallback="D34D")
            self.D_FILE = args.get("dns", "file", fallback="D34D")
            self.D_TIME_SECS = args.get("dns", "time_limit", fallback="D34D")
            self.D_TIME_SECS = int(self.D_TIME_SECS) if not self.D_TIME_SECS == '' else None
            
            #URLSTALKER
            self.U_ENABLED = args.getboolean("urlstalker", "enabled", fallback="D34D")
            self.U_TIME_SECS = args.get("urlstalker", "time_limit", fallback="D34D")
            self.U_TIME_SECS = int(self.U_TIME_SECS) if not self.U_TIME_SECS == '' else None
            
            #JS
            self.J_ENABLED = args.getboolean("js", "enabled", fallback="D34D")
            
            
            
            
        except Exception as err:
            log.error("Error (" + str(err) + ") while trying to read values from config file. Please, download the config file again.")
            sys.exit()
        self.check_args()
        
    def check_args(self):
        if "D34D" in self.__dict__.values():
            #si alguno de los atributos de la clase args contiene D34D, es porque no se ha encontrado alguno de los args
            log.error("Missing conf parameters in config file. Leaving...")
            sys.exit()
            
        #PARTICULARES
        if self.A_ENABLED and self.A_INTERVAL == 0:
            log.warning("ARPS interval can't be 0. Setting to 1...")
            self.A_INTERVAL = 1
        if self.A_ENABLED and (not self.A_TARGET_IP or not self.A_GATEWAY_IP or not self.A_INTERVAL):
            #si algun valor esta vacio... solo TIME_SECS y DISCONNECT pueden estar vacios o ser None/False
            log.warning("Values of ARPS parameters in config file are not valid. Disabling ARPS...")
            self.A_ENABLED = False
        if self.D_ENABLED and not self.D_FILE:
            log.warning("Values of DNS parameters in config file are not valid. Disabling DNS...")
            self.D_ENABLED = False
        
        #NO PARTICULARES
        if self.D_ENABLED and not self.A_ENABLED:
            #dns sin arps esta feo
            log.warning("DNS Spoofing can't be done without ARP Spoofing. Please enable ARPS. Disabling DNS...")
            self.D_ENABLED = False
            
        if self.S_ENABLED and not self.A_ENABLED:
            log.warning("ARP Spoofing is disabled! Only packets from the local machine will be sniffed. You can activate it in the config file.")
            
        if not self.N_ENABLED and not self.S_ENABLED and not self.A_ENABLED and not self.D_ENABLED and not self.U_ENABLED and not self.J_ENABLED:
            log.error("No module is enabled. Leaving...")
            sys.exit()
        
        log.info("CONFIG", "Config file is OK!")


def configure_iptables(init, arps_activated=False, dns_activated=False, js_activated=False):
    if platform == "linux": #platform is from scapy
        os.system("iptables --flush")
        if init:
            if arps_activated: os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            if dns_activated: 
                os.system("iptables -A FORWARD -p udp --dport 53 -j DROP");
                os.system("iptables -A FORWARD -p tcp --dport 80 -m string --string 'GET' --algo bm -m string --string 'GET' --algo bm -j DROP")
                
            if js_activated: os.system("iptables -A FORWARD -p tcp --sport 80 -j DROP")
            
            log.info("CONFIG", "Iptables have been established.")
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            log.info("CONFIG", "Iptables have been cleared.")
    else:
        if init:
            if arps_activated: log.warning("Make sure Routing and Remote Access Service is activated.")
            if dns_activated: log.warning("Windows is not supported due to the lack of iptables. DNS Spoofing will probably not work correctly.")
            
            
def intro(quality):

    width = os.get_terminal_size().columns - 2

    
    log.header(" ___  ___    ___   ________    ________       ".center(width))
    log.header("|\  \|\  \  |\  \ |\   ____\  |\   ____\     ".center(width))
    log.header("\ \  \/  /|_\ \  \\\ \  \___|_ \ \  \___|_    ".center(width))
    log.header(" \ \   ___  \\\ \  \\\ \_____  \ \ \_____  \   ".center(width))
    log.header("  \ \  \\\ \  \\\ \  \\\|____|\  \ \|____|\  \  ".center(width))
    log.header("   \ \__\\\ \__\\\ \__\ ____\_\  \  ____\_\  \ ".center(width))
    log.header("    \|__| \|__| \|__||\_________\|\_________\ ".center(width))
    log.header("                     \|_________|\|_________| ".center(width) + "\n")
    print("       Klecko Is Spoofing and Sniffing".center(width) + "\n")


def wait_until_all_threads_terminate2():
    #second way
    
    
    while len(threading.enumerate()) > N_THREADS: 
        try:
            time.sleep(0.2)
        except KeyboardInterrupt:
            pass
            

def dependencias():
    f = open(scapy.__path__[0] + "/sendrecv.py")
    content = f.read()
    f.close()
    if scapy.VERSION < "2.4.0":
        log.error("Scapy " + scapy.VERSION + "is not supported. Please download Scapy +2.4.0.")
    if not "KLECKO" in content:
        log.error("Your sendrecv.py Scapy file is not Klecko's scapy file. Please download it from his Google Drive.")
        sys.exit()
    


def main():
    intro("marvelous")
    log.greetings("WELCOME", "Welcome to KISS.")
    
    dependencias()
    
    args = Args("config.ini")
    
    arps_activated = (args.A_ENABLED or args.N_PASSIVE_ARPS_EVERYONE)
    configure_iptables(True, arps_activated, args.D_ENABLED, args.J_ENABLED)
    
    exit_event = threading.Event()
    
    if args.N_ENABLED:
        #not a thread
        net = netanalyzer.Network_Analyzer(args.N_GATEWAY, args.N_RESOLVE, args.N_ACTIVE, args.N_PASSIVE, args.N_PASSIVE_ARPS_EVERYONE ,args.N_PASSIVE_TIMEOUT)
        net.start()

    
    if args.A_ENABLED:
        arp_spoofer1 = arp.ARP_Spoofer(exit_event, args.A_TARGET_IP, args.A_GATEWAY_IP, args.A_TIME_SECS, args.A_INTERVAL, args.A_DISCONNECT)
        arp_spoofer1.start()
        if args.A_TARGET_IP != "everyone":
            arp_spoofer2 = arp.ARP_Spoofer(exit_event, args.A_GATEWAY_IP, args.A_TARGET_IP, args.A_TIME_SECS, args.A_INTERVAL, args.A_DISCONNECT)
            arp_spoofer2.start()
        
    if args.D_ENABLED:
        dns_spoofer = dns.DNS_Spoofer(exit_event, args.D_FILE, args.D_TIME_SECS)
        dns_spoofer.start()
   
    if args.S_ENABLED:
        sniffer = sniffing_http.HTTP_Sniffer(exit_event, args.S_ATTRIBUTES, args.S_TIME_SECS)
        sniffer.start()
        
    if args.U_ENABLED:
        url = url_stalker.URL_Stalker(exit_event, args.U_TIME_SECS)
        url.start()
        
    if args.J_ENABLED:
        js_injecter = js.JS_Injecter(exit_event)
        js_injecter.start()
        
    
    while not exit_event.is_set() and len(threading.enumerate()) > N_THREADS:
        try:
            time.sleep(0.5)
        except KeyboardInterrupt:
            exit_event.set()
            log.info("INFO", "Finishing every module...")
            
    wait_until_all_threads_terminate2()
    configure_iptables(False)
    #log.error("This is an error exampleLALIASTEWEY")
    log.greetings("BYE", "Hope you enjoyed! KleSoft\n")
    
            
if __name__ == "__main__":
    main()

