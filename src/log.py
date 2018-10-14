import configparser
import random
from scapy.all import platform

if platform == "linux":
    class colors(): #https://i.imgur.com/jtB7XMC.png
        FAIL = '\033[41m'
        GREETINGS = '\033[91m'
        DNS = '\033[92m'
        ARPS = '\033[93m'
        WARNING = '\033[43m'
        URLSTALKER = '\033[34m'
        JS = '\033[94m'
        INFO = '\033[95m'
        NETANALYZER = '\033[36m'
        SNIFF = '\033[96m'
        

        HEADER = '\033[' + str(random.choice([31, 91, 32, 92, 33, 93, 94, 95, 36])) + 'm'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
else:
    class colors(): #https://i.imgur.com/jtB7XMC.png
        FAIL = ''
        DNS = ''
        WARNING = ''
        ARPS = ''
        HEADER = ''
        SNIFF = ''

        ENDC = ''
        BOLD = ''
        UNDERLINE = ''

reader = configparser.ConfigParser()
reader.read("verbose.ini")

class verbose(): #verbose class, which will contain an attribute for each module verbose settings.
    verbose = reader.getboolean("general", "verbose")
    
    class sniff():
        verbose = reader.getboolean("sniff", "verbose")
        permission_sniffing = reader.getboolean("sniff", "permission_sniffing")
        start = reader.getboolean("sniff", "start")
        finish = reader.getboolean("sniff", "finish")
        packet_found = reader.getboolean("sniff", "packet_found")
        cookies_found = reader.getboolean("sniff", "cookies_found")
        results = reader.getboolean("sniff", "results")
        
    class arps():
        verbose = reader.getboolean("arps", "verbose")
        start = reader.getboolean("arps", "start")
        finish = reader.getboolean("arps", "finish")
        target_everyone = reader.getboolean("arps", "target_everyone")
        
    class dns():
        verbose = reader.getboolean("dns", "verbose")
        len = reader.getboolean("dns", "len")
        resolve = reader.getboolean("dns", "resolve")
        permission_sniffing = reader.getboolean("dns", "permission_sniffing")
        start = reader.getboolean("dns", "start")
        finish = reader.getboolean("dns", "finish")
        dns_query = reader.getboolean("dns", "dns_query")
        http_request = reader.getboolean("dns", "http_request")
        resolve1 = reader.getboolean("dns", "resolve1")
        resolve2 = reader.getboolean("dns", "resolve2")
    
    class urlstalker():
        verbose = reader.getboolean("urlstalker", "verbose")
        start = reader.getboolean("urlstalker", "start")
        finish = reader.getboolean("urlstalker", "finish")
        http = reader.getboolean("urlstalker", "http")
        https = reader.getboolean("urlstalker", "https")
        
    class js():
        verbose = reader.getboolean("js", "verbose")
        start = reader.getboolean("js", "start")
        finish = reader.getboolean("js", "finish")
        packet_handled = reader.getboolean("js", "packet_handled")
        gzipped_empty_packet = reader.getboolean("js", "gzipped_empty_packet")
        exceeded_len = reader.getboolean("js", "exceeded_len")
        gzipped_uncomplete_packet = reader.getboolean("js", "gzipped_uncomplete_packet")
        

        
    

class log(): #log class, which will contain a class for each module.
    #each message has a key which identifies it, and it corresponds to the key of the same name in the class verbose.
    def greetings(header, *msg):
        print(colors.GREETINGS + "[" + header + "]" + colors.ENDC, *msg)
        
    def info(header, *msg):
        print(colors.INFO + "[" + header + "]" + colors.ENDC, *msg)
    
    def warning(module_and_module_key, *msg):
        print(colors.WARNING + colors.BOLD + "[WARNING]" + colors.ENDC + " ", end="")
        
        if type(module_and_module_key) == tuple:
            print(eval("colors." + module_and_module_key[0].upper()) + "[" + module_and_module_key[1] + "]", colors.ENDC, end="")
        elif type(module_and_module_key) == str:
            print(eval("colors." + module_and_module_key.upper()) + "[" + module_and_module_key.upper() + "]", colors.ENDC, end="")

        print(*msg)
            
    
    def error(module_and_module_key, *msg):
        print(colors.FAIL + colors.BOLD + "[ERROR]" + colors.ENDC + " ", end="")
        
        if type(module_and_module_key) == tuple:
            print(eval("colors." + module_and_module_key[0].upper()) + "[" + module_and_module_key[1] + "]", colors.ENDC, end="")
        elif type(module_and_module_key) == str:
            print(eval("colors." + module_and_module_key.upper()) + "[" + module_and_module_key.upper() + "]", colors.ENDC, end="")
            
        print(*msg)
        
    def header(*msg):
        print(colors.HEADER, *msg, colors.ENDC)
        
    def check_verbose(module, msg_key):
        return (eval("verbose." + module + ".verbose") and eval("verbose." + module + "." + msg_key))
    
    def print_log_header(module, msg_key, module_key):
        if verbose.verbose:
            if log.check_verbose(module, msg_key):
                print(eval("colors." + module.upper()) + "[" + module_key + "]", colors.ENDC, end="")
    
    
    class netanalyzer():
        def info(msg_key, **kwargs):
            if verbose.verbose:
                print(colors.NETANALYZER + "[NET]", colors.ENDC, end="")
                if msg_key == "start":
                    if kwargs["type"] == "active":  print("Performing active network analysis...")
                    elif kwargs["type"] == "passive": 
                        print("Passive scanning will be performed for", kwargs["timeout"], "seconds. ",end="")
                        if kwargs["arps"]: print("ARPS everyone method was chosen. It may be a bit dangerous but also quite effective. ", end="")
                        print("If a new device is detected, it will be printed below. Press CTRL-C if you wish to stop before. Results:\n")
                
                elif msg_key == "finish":
                    if kwargs["type"] == "active":          print("Active scanning finished. Devices detected:", kwargs["devices"])
                    elif kwargs["type"] == "active_only":   print("Active scanning finished. Devices detected:", str(kwargs["devices"]) + ". Results:\n")
                    elif kwargs["type"] == "passive":       print("Scanning finished. Total scanning duration:", kwargs["time"], "seconds. Total devices detected:", kwargs["devices"])

    class sniff():
        def info(msg_key, **kwargs):
            if log.check_verbose("sniff", msg_key):
                print(colors.SNIFF + "[SNIFFER]", colors.ENDC, end="")
                
                if msg_key == "start":          print("Sniffing HTTP packets... ", end=""); print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":       print("Sniffing HTTP packets finished! ", end=""); print(kwargs["len"], "packets found! Packets are saved in", kwargs["loc"], end="") if kwargs["len"] > 0 else print("No packets found.", end="")
                elif msg_key == "packet_found": print("New packet found in host", kwargs["host"], "from IP", kwargs["src"])
                elif msg_key == "cookies_found":print("New cookies found in host", kwargs["host"], "from IP", kwargs["src"] + ":", kwargs["cookies"])
                    
                
        def error(msg_key, **kwargs):
            #print(colors.SNIFF + "[SNIFFER]", colors.ENDC, end="")
            if msg_key == "permission_sniffing": log.error(("sniff", "SNIFFER"), "PermissionError at sniffing: ", kwargs["err"].strerror + "; number:", str(kwargs["err"].errno) + ". Are you admin?")
            
                
                
    class arps():
        def info(msg_key, **kwargs):
            if log.check_verbose("arps", msg_key):
                print(colors.ARPS + "[ARPS]", colors.ENDC, end="")
                
                if msg_key == "start":      print("ARP Spoofing", kwargs["target"], "with an interval of", kwargs["interval"], "secs. Disconnect: " + kwargs["disconnect"] + ". ", end = ""); print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":   print("ARP Spoofing finished!", kwargs["target"], "is sending packets to", kwargs["gateway"], "again.") if kwargs["disconnect"] else print("ARP Spoofing finished! No more packets from", kwargs["target"])
                
                
        
        def warning(msg_key, **kwargs):
            if log.check_verbose("arps", msg_key):
                #print(colors.ARPS + "[ARPS]", colors.ENDC, end="")
                
                if msg_key == "target_everyone": log.warning("arps", "Targetting every device in the network does not support two-sides-MITM. Only client-->server is supported.")
                
                
                    
    
    class dns():
        def info(msg_key, **kwargs):
            if log.check_verbose("dns", msg_key):
                print(colors.DNS + "[DNS]", colors.ENDC, end="")
                
                if msg_key == "start":          print("DNS Spoofing started. ", end=""); print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":       print("DNS Spoofing finished!")
                elif msg_key == "dns_query":    print("Target DNS query packet asking for", kwargs["domain_queried"], "Redirecting to", kwargs["ip_redirect"])
                elif msg_key == "http_request": print("Target HTTP get request asking for", kwargs["host"] + ". Redirecting to", kwargs["spoofed_domain"])
                elif msg_key == "resolve1":     print("Host", kwargs["supposed_ip"], "is not an IP. Resolving domain...")
                elif msg_key == "resolve2":     print("Domain", kwargs["supposed_ip"], "resolved:", kwargs["true_ip"])
                
                    
        def error(msg_key, **kwargs):
            #print(colors.DNS + "[DNS]", colors.ENDC, end="")
            
            if msg_key == "len":                    log.error("dns", "Spoofed packet length was more than expected. There was a difference of", kwargs["diff1"], "in SEQS+TCPLENS. After ussing solution 3 there's a difference of", kwargs["diff2"], "which is still bad.")
            elif msg_key == "resolve":              log.error("dns", "Domain", kwargs["supposed_ip"], "could not be resolved, so it won't be redirected. Is it well written??")
            elif msg_key == "permission_sniffing":  log.error("dns", "PermissionError at sniffing: ", kwargs["err"].strerror + "; number:", str(kwargs["err"].errno) + ". Are you admin?")
            
    
    
    
    class urlstalker():
        def info(msg_key, **kwargs):
            if log.check_verbose("urlstalker", msg_key):
                print(colors.URLSTALKER + "[URLStalker]", colors.ENDC, end="")
                
                if msg_key == "start":      print("URL Stalking started. ",end=""); print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":   print("URL Stalking finished.")
                elif msg_key == "http":     print("HTTP url detected:", kwargs["url"], "from", kwargs["src"])
                elif msg_key == "https":    print("HTTPS host detected:", kwargs["url"], "from", kwargs["src"])
                
    
    
    class js():
        def warning(msg_key, **kwargs):
            if log.check_verbose("js", msg_key):
                #print(colors.JS + "[JS]", colors.ENDC, end="")
                
                if msg_key=="gzipped_empty_packet":     	log.warning("js", "Gzipped packet with no load appart from http headers arrived. Forwarding without injecting...")
                elif msg_key=="exceeded_len":   			log.warning("js", "Despite having removed attributes, length was reduced from", kwargs["len_load"], "to", kwargs["len_new_load"], "and not to", kwargs["len_needed"], "(" + kwargs["len_difference"] + " more bytes than intended)")
                elif msg_key=="gzipped_uncomplete_packet":	log.warning("js", "EOFError decompressing gzip packet (probably the packet was not complete). Forwarding without injecting...")
               
        def info(msg_key, **kwargs):
            if log.check_verbose("js", msg_key):
                print(colors.JS + "[JS]", colors.ENDC, end="")
                
                if msg_key=="start":                print("JS Injecter started with target", kwargs["target"] + ". ",end=""); print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key=="finish":             print("JS Injecter finished.")
                elif msg_key == "packet_handled":   print("Sent spoofed packet. Spoof load length:", kwargs["len_spoof_load"], "Real load length:", kwargs["len_real_load"])
        

