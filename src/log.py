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
        packet_len = reader.getboolean("js", "packet_len")
        out_of_order = reader.getboolean("js", "out_of_order")
        repeated = reader.getboolean("js", "repeated")
        psh_ack_not_last = reader.getboolean("js", "psh_ack_not_last")
        recv1 = reader.getboolean("js", "recv1")
        recv2 = reader.getboolean("js", "recv2")
        recv3 = reader.getboolean("js", "recv3")
        recv_seq = reader.getboolean("js", "recv_seq")
        sent_spoofed = reader.getboolean("js", "sent_spoofed")
        
    

class log(): #log class, which will contain a class for each module.
    #each message has a key which identifies it, and it corresponds to the key of the same name in the class verbose.
    def greetings(header, *msg):
        print(colors.GREETINGS + "[" + header + "]" + colors.ENDC, *msg)
        
    def info(header, *msg):
        print(colors.INFO + "[" + header + "]" + colors.ENDC, *msg)
    
    def warning(*msg):
        print(colors.WARNING + colors.BOLD + "[WARNING]" + colors.ENDC, *msg)
    
    def error(*msg):
        print(colors.FAIL + colors.BOLD + "[ERROR]" + colors.ENDC, *msg)
        
    def header(*msg):
        print(colors.HEADER, *msg, colors.ENDC)
        
    def print_log_header(module, msg_key, module_key):
        if verbose.verbose:
            if eval("verbose." + module + "." + msg_key):
                print(eval("colors." + module.upper()) + "[" + module_key + "]", colors.ENDC, end="")
        
    
    class netanalyzer():
        def info(msg_key, **kwargs):
            if verbose.verbose:
                print(colors.NETANALYZER + "[NET]", colors.ENDC, end="")
                if msg_key == "start":
                    if kwargs["type"] == "active": print("Performing active network analysis...")
                    elif kwargs["type"] == "passive": 
                        print("Passive scanning will be performed for", kwargs["timeout"], "seconds. ",end="")
                        if kwargs["arps"]: print("ARPS everyone method was chosen. It may be a bit dangerous but also quite effective. ", end="")
                        print("If a new device is detected, it will be printed below. Press CTRL-C if you wish to stop before. Results:\n")
                elif msg_key == "finish":
                    if kwargs["type"] == "active": print("Active scanning finished. Devices detected:", kwargs["devices"])
                    elif kwargs["type"] == "active_only": print("Active scanning finished. Devices detected:", str(kwargs["devices"]) + ". Results:\n")
                    elif kwargs["type"] == "passive": print("Scanning finished. Total scanning duration:", kwargs["time"], "seconds. Total devices detected:", kwargs["devices"])
                        
                        
    # ~ if self.active and self.passive: 
        # ~ print("[NET] Active scanning finished with", len(self.hosts), "devices detected.")
        # ~ print("[NET] Passive scanning will be performed for", str(self.timeout), "seconds. If a new device is detected, it will be printed below. Press CTRL-C if you wish to stop before. Results:\n")
    
    # ~ elif self.passive: print("[NET] Passive scanning will be performed for", str(self.timeout), "seconds. If a new device is detected, it will be printed below. Press CTRL-C if you wish to stop before. Results:\n")
    # ~ elif self.active: print("[NET] Active scanning finished with", len(self.hosts), "devices detected. Results:\n"))
    
    # ~ print("Results:\n")
    # ~ for host in self.hosts:
        # ~ self.display_host(host)
    
    
    
    class sniff():
        def info(msg_key, **kwargs):
            if verbose.verbose and verbose.sniff.verbose:
                #print(colors.SNIFF + "[SNIFFER]", colors.ENDC, end="")
                log.print_log_header("sniff", msg_key, "SNIFFER")
                if msg_key == "start":
                    if verbose.sniff.start: 
                        print("Sniffing HTTP packets... ", end="")
                        print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                        
                elif msg_key == "finish":
                    if verbose.sniff.finish:
                        print("Sniffing HTTP packets finished! ", end="")
                        if kwargs["len"] > 0:
                            print(kwargs["len"], "packets found! Packets are saved in", kwargs["loc"], end="")
                        else:
                            print("No packets found.", end="")
                
                elif msg_key == "packet_found":
                    if verbose.sniff.packet_found: print("New packet found in host", kwargs["host"], "from IP", kwargs["src"])
                
                elif msg_key == "cookies_found":
                    if verbose.sniff.cookies_found: print("New cookies found in host", kwargs["host"], "from IP", kwargs["src"] + ":", kwargs["cookies"])

                else: log.warning("LOG ERROR while trying to log info in sniff. Unknown message key:", msg_key)
                    #print(colors.WARNING + "[WARNING]", colors.ENDC, "LOG ERROR while trying to log info in sniff. Unknown message key:", msg_key)
                
        def error(msg_key, **kwargs):
            if msg_key == "permission_sniffing": log.error("PermissionError at sniffing: ", kwargs["err"].strerror + "; number:", str(kwargs["err"].errno) + ". Are you admin?")
            else: log.warning("LOG ERROR while trying to log error in sniff. Unknown message key:", msg_key)
                #print(colors.WARNING + "[WARNING]", colors.ENDC, " LOG ERROR while trying to log error in sniff. Unknown message key:", msg_key)
           
                
                
    class arps():
        def info(msg_key, **kwargs):
            if verbose.verbose and verbose.arps.verbose:
                #print(colors.ARPS + "[ARPS]", colors.ENDC, end="")
                log.print_log_header("arps", msg_key, "ARPS")
                if msg_key == "start":
                    if verbose.arps.start:
                        print("ARP Spoofing", kwargs["target"], "with an interval of", kwargs["interval"], "secs. Disconnect: " + kwargs["disconnect"] + ". ", end = "")
                        print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                        
                elif msg_key == "finish":
                    if verbose.arps.finish:
                        if kwargs["disconnect"]:    print("ARP Spoofing finished!", kwargs["target"], "is sending packets to", kwargs["gateway"], "again.")
                        else:                       print("ARP Spoofing finished! No more packets from", kwargs["target"])
                
                else: log.warning("LOG ERROR while trying to log info in arps. Unknown message key:", msg_key)
                    #print(colors.WARNING + "[WARNING]", colors.ENDC, "LOG ERROR while trying to log info in arps. Unknown message key:", msg_key)
        
        def warning(msg_key, **kwargs):
            if verbose.verbose and verbose.arps.verbose:
                if msg_key == "target_everyone":
                    if verbose.arps.target_everyone: log.warning("Targetting every device in the network does not support two-sides-MITM. Only client-->server is supported.")
                        #print(colors.WARNING + "[WARNING]", colors.ENDC, "Targetting every device in the network does not support two-sides-MITM. Only client-->server is supported.")
                
                else: log.warning( "LOG ERROR while trying to log warning in arps. Unknown message key:", msg_key)
                    #print(colors.WARNING + "[WARNING]", colors.ENDC, "LOG ERROR while trying to log warning in arps. Unknown message key:", msg_key)
    
    class dns():
        def info(msg_key, **kwargs):
            if verbose.verbose and verbose.dns.verbose:
                #print(colors.DNS + "[DNS]", colors.ENDC, end="")
                log.print_log_header("dns", msg_key, "DNS")
                if msg_key == "start":
                    if verbose.dns.start: 
                        print("DNS Spoofing started. ", end="")
                        print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":
                    if verbose.dns.finish: print("DNS Spoofing finished!")
                elif msg_key == "dns_query":
                    if verbose.dns.dns_query: print("Target DNS query packet asking for", kwargs["domain_queried"], "Redirecting to", kwargs["ip_redirect"])
                elif msg_key == "http_request":
                    if verbose.dns.http_request: print("Target HTTP get request asking for", kwargs["host"] + ". Redirecting to", kwargs["spoofed_domain"])
                elif msg_key == "resolve1":
                    if verbose.dns.resolve1: print("Host", kwargs["supposed_ip"], "is not an IP. Resolving domain...")
                elif msg_key == "resolve2":
                    if verbose.dns.resolve2: print("Domain", kwargs["supposed_ip"], "resolved:", kwargs["true_ip"])
                else: log.warning("LOG ERROR while trying to log info in dns. Unknown message key:", msg_key)
                    
        def error(msg_key, **kwargs):
            if msg_key == "len": log.error("Spoofed packet length was more than expected. There was a difference of", kwargs["diff1"], "in SEQS+TCPLENS. After ussing solution 3 there's a difference of", kwargs["diff2"], "which is still bad.")
            elif msg_key == "resolve": log.error("Domain", kwargs["supposed_ip"], "could not be resolved, so it won't be redirected. Is it well written??")
            elif msg_key == "permission_sniffing": log.error("PermissionError at sniffing: ", kwargs["err"].strerror + "; number:", str(kwargs["err"].errno) + ". Are you admin?")
            else: log.warning("LOG ERROR while trying to log error in dns. Unknown message key:", msg_key)
    
    
    
    class urlstalker():
        def info(msg_key, **kwargs):
            if verbose.verbose and verbose.urlstalker.verbose:
                #print(colors.URLSTALKER + "[URLStalker]", colors.ENDC, end="")
                log.print_log_header("urlstalker", msg_key, "URLStalker")
                if msg_key == "start":
                    if verbose.urlstalker.start:
                        print("URL Stalking started. ",end="")
                        print("Time limit:", kwargs["timeout"], "seconds.") if kwargs["timeout"] else print("No time limit.")
                elif msg_key == "finish":
                    if verbose.urlstalker.finish: print("URL Stalking finished.")
                elif msg_key == "http":
                    if verbose.urlstalker.http: print("HTTP url detected:", kwargs["url"], "from", kwargs["src"])
                elif msg_key == "https":
                    if verbose.urlstalker.https: print("HTTPS host detected:", kwargs["url"], "from", kwargs["src"])
                else: log.warning("LOG ERROR while trying to log info in url. Unknown message key:", msg_key)
    
    
    class js():
        def error_decompressing(ack_n, err):
            print("[ID " + str(ack_n) + "][ERROR] ",end="")
            if type(err) == EOFError:
                print("End Of File Error trying to decompress packet load (gzip) in order to get the JS code. There may be an uncaptured packet. A later attempt to get the code is recommended.")
            else:
                print("Unknown error trying to decompress packet load (gzip) in order to get the JS code:", err, ". A later attempt to get the code is recommended.")

        def warning(msg_key, **kwargs):
            if verbose.verbose and verbose.js.verbose:
                if msg_key=="packet_len":
                    if verbose.js.packet_len: print("[ID", str(kwargs["id"]) + "][SEQ " + str(kwargs["seq"]) + "][WARNING] Packet load length exceeded 1410 bytes. Current length:", kwargs["length"], "Spoofed:", kwargs["spoofed"])
                elif msg_key=="out_of_order":
                    if verbose.js.out_of_order: print("[ID", str(kwargs["id"]) + "][SEQ " + str(kwargs["seq"]) + "][WARNING] Out of order packet received.")
                elif msg_key=="repeated":
                    if verbose.js.repeated: print("[ID", str(kwargs["id"]) + "][SEQ " + str(kwargs["seq"]) + "][RAW " + str(kwargs["has_raw"]) + "][WARNING] Repeated packet received.")
                elif msg.key=="psh_ack_not_last":
                    if verbose.js.psh_ack_not_last: print("[ID", str(kwargs["id"]) + "][SEQ " + str(kwargs["seq"]) + "][WARNING] PSH/ACK packet receives with a load length of 1410. It is not the last packet of the transaction.")
                else: log.warning("LOG ERROR while trying to log warning in js. Unknown message key:", msg_key)
                
        def info_packet_traffic(p_ack_number, msg_key, **kwargs):
            if verbose.verbose and verbose.js.verbose:
                if msg_key=="recv1":
                    if verbose.js.recv1: print("[ID " + str(p_ack_number) + "][SEQ " + str(kwargs["seq"]) + "] Recv: first packet of a JS transaction.")
                elif msg_key=="recv2":
                    if verbose.js.recv2: print("[ID " + str(p_ack_number) + "][SEQ " + str(kwargs["seq"]) + "] Recv: first and only packet of a JS transaction.")
                elif msg_key=="recv3":
                    if verbose.js.recv3: print("[ID " + str(p_ack_number) + "][SEQ " + str(kwargs["seq"]) + "] Recv: ultimo paquete de transaccion de JS. Finalizada transaccion de longitud", kwargs["length"])
                elif msg_key=="recv_seq":
                    if verbose.js.recv_seq: print("[ID " + str(p_ack_number) + "][SEQ " + str(kwargs["seq"]) + "] Recv: SEQ:", kwargs["seq"], kwargs["seqs"])
                elif msg_key=="sent_spoofed":
                    if verbose.js.sent_spoofed: print("[ID " + str(p_ack_number) + "] Sent: spoofed answer.")
                else: log.warning("LOG ERROR while trying to log info in js. Unknown message key:", msg_key)
       
