from scapy.all import *
from urllib.request import unquote
from urllib.parse import parse_qs


def get_checksum(pkt, layer):
    """Gets the checksum of a layer from a packet.
    
    Parameters:
        pkt (scapy.packet.Packet): packet from which the checksum will be
            obtained.
        layer (str, layer from scapy.layers): the layer of the packet from
            which the checksum will be obtained. Examples: IP, TCP.
    
    Returns:
        str: the checksum desired.
    """
    if pkt[layer].chksum:
        return pkt[layer].chksum
    else: #if the chksum is None, it calculates it
        chksum = pkt.__class__(bytes(pkt))[layer].chksum
        return chksum


def get_user_agents(load):
    """Gets the User Agents from a HTTP packet load.
    
    Parameters:
        load (str): HTTP packet load.
    
    Returns:
        str: string containing the User Agents of the load.
    """
    first_pos = load.find(b"User-Agent: ")+12
    agent = load[first_pos:load.find(b"\r\n", first_pos)]
    return agent


def is_it_an_ip(s):
    """Checks if the given string is an IP Address or not.
    
    Parameters:
        s (str): string that may contain an IP Address.
    
    Returns:
        bool: True if it is an IP Address, False otherwise
    """
    if s.replace(".","").isnumeric():
        parts = s.split(".")
        if len(parts) == 4:
            for part in parts:
                if int(part) > 255 or int(part) < 0:
                    return False
                return True
    return False
    
    
def get_domain_pointer_to_local_ip(ip):
    """Given a local IP address gets the local domain that points to that IP.
    
    Parameters:
        ip (str): the local IP address from which the domain will be made.
        
    Returns:
        str: local domain pointing to that local IP Address.
    
    Example:
        get_domain_pointer_to_local_ip("192.168.191.120") returns
            120.191.168.192.in-addr.arpa
    """
    ip_split = ip.split(".")
    ip_split = ip_split[::-1]
    ip_pointer = ".".join(ip_split) + ".in-addr.arpa"
    return ip_pointer


def nslookup(domain, ns_server="8.8.8.8", qtype="A", timeout=2, twice=True):
    """Makes a DNS Query to a server.
    
    Parameters:
        domain (str): the domain that will be resolved by the server.
        ns_server (str): the server that will resolve the domain. Default is
            8.8.8.8 which is Google server.
        qtype (str): query type. Default is A, which is IPv4.
        timeout (int): time in secs to wait for a response.
        twice (bool): if set to True, there will be two attempts to get a
            response.
    
    Returns:
        str: the IP address of the domain.
        None: the domain could not be resolved.
    """
    
    p = IP(dst=ns_server)/UDP(dport=53)/DNS(qd=DNSQR(qname=domain, qtype=qtype))
    ans = sr1(p, timeout=timeout, verbose=0)
    if ans and ans.rcode == 0: #si hay repsuesta y viene sin error
        result = ans["DNS"].an.rdata
        if type(result) == bytes: result = result.decode("utf-8")
        return result
    else:
        if twice:
            return nslookup(domain, ns_server, qtype, timeout, False)
        else:
            return None


def get_host(packet_load):
    """Gets the host a HTTP packet was sent to.
    
    Parameters:
        packet_load (str, bytes): the load of the HTTP packet.
    
    Returns:
        str: the host the packet was sent to.
    """
    
    if type(packet_load) == bytes: packet_load = packet_load.decode()
        
    pos1 = packet_load.find("Host: ")
    if pos1 != -1:
        pos2 = packet_load.find("\r", pos1)
        result = unquote(packet_load[pos1+6:pos2])
        return result
    return ""

        
def get_subhost(packet_load):
    """Gets the URL inside the host a HTTP packet was sent to.
    
    Parameters:
        packet_load (str): the load of the HTTP packet.
    
    Returns:
        str: the URL inside the host the packet was sent to.
    """
    if type(packet_load) == bytes: packet_load = packet_load.decode()
    
    last_pos = packet_load.find(" HTTP/")
    if packet_load[:4] == "POST":
        first_pos = 5
    elif packet_load[:3] == "GET":
        first_pos = 4
    else:
        print("get_subhost: packet was not get or post.")
        print(packet_load)
        return ""
        
    return unquote(packet_load[first_pos:last_pos])


# ~ def get_attribute_from_packet_load(attribute, packet_load):
        # ~ #Gets an attribute from the load of a packet. This load is located in the raw layer of the packet.
        # ~ #Example: looking for 'pepito' in '...webm.orange.es%2F&usuario=pepito&dominio=orangecorreo.es&...'.
        # ~ #Then we should do get_attribute_from_packet(usuario, packet_load)
        
        # ~ packet_load = packet_load.lower()
        # ~ pos1 = packet_load.find(attribute + "=")
        # ~ if pos1 != -1:
            # ~ pos2 = packet_load.find("&", pos1) #it finds where the next attribute starts, which is the end of our attribute
            # ~ if pos2 == -1:
                # ~ #if it doesnt find it, it means the attribute is the last one, so it must get it from pos1 to the end of the string
                # ~ result = unquote(packet_load[pos1+len(attribute)+1:])
            # ~ else:
                # ~ result = unquote(packet_load[pos1+len(attribute)+1:pos2]) #+1 is because of the '=': &usuario=pepito&
            # ~ #if the username were 'pep&ito', it would be changed to 'pep%26ito' because it has been quoted. so i have to unquote it.
            
            # ~ return result
        # ~ return None
    
            
def get_relevant_data_from_http_packet(relevant_attributes, packet):
    """Gets all the relevant data of a form from a HTTP post packet.
    
    Parameters:
        relevant_attributes (list, str): this can be a list with every
            attribute that will be looked for, or a string with '*', meaning
            that every attribute is relevant.
        packet (scapy.packet.Packet): HTTP post packet.
        
    Returns:
        dict: dictionary containing the attributes and values sent by the
            HTTP post packet.
    """
    
    get_cookies = False
    if "cookie" in "".join(relevant_attributes).lower():
        get_cookies = True
        
    
    load = packet["Raw"].load.decode("utf-8", "ignore")
    form_load = load[load.find("\r\n\r\n")+4:]
    form_load_parsed = parse_qs(form_load,errors="backslashreplace")
    
    data = {"ip source":packet["IP"].src, "host":get_host(load)+get_subhost(load)}
    
    # ~ print(load)
    if relevant_attributes == "*":
        for item in form_load_parsed.items():
            data[item[0]] = item[1][0]
        cookies = get_header_attribute_from_http_load("Cookie", load.encode()).decode()
        if cookies: data["Cookies"] = cookies[8:-2]
    else:
        for attribute in relevant_attributes:
            possible_value = form_load_parsed.get(attribute)#get_attribute_from_packet_load(attribute, load)
            if possible_value:
                data[attribute] = possible_value[0]
        if get_cookies:
            cookies = get_header_attribute_from_http_load("Cookie", load.encode()).decode()
            if cookies: data["Cookies"] = cookies[8:-2]
    return data


def get_header_attribute_from_http_load(attribute, load):
    #Returns a string containing the attribute, its value and the \r\n
    first_pos = load.find(attribute.encode())
    if first_pos != -1:
        last_pos = load.find(b"\r\n", first_pos) +2
        data = load[first_pos:last_pos]
        return data
    return b""
