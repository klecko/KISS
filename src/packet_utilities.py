from scapy.all import *
from urllib.request import unquote
from urllib.parse import parse_qs



def is_it_an_ip(s):
    if s.replace(".","").isnumeric():
        parts = s.split(".")
        if len(parts) == 4:
            for part in parts:
                if int(part) > 255 or int(part) < 0:
                    return False
                return True
    return False
    
    
def get_domain_pointer_to_local_ip(ip):
    ip_split = ip.split(".")
    ip_split = ip_split[::-1]
    ip_pointer = ".".join(ip_split) + ".in-addr.arpa"
    return ip_pointer


def nslookup(domain, ns_server="8.8.8.8", qtype="A", timeout=2, once=False):
    p = IP(dst=ns_server)/UDP(dport=53)/DNS(qd=DNSQR(qname=domain, qtype=qtype))
    ans = sr1(p, timeout=timeout, verbose=0)
    if ans and ans.rcode == 0: #si hay repsuesta y viene sin error
        result = ans["DNS"].an.rdata
        if type(result) == bytes: result = result.decode("utf-8")
        return result
    else:
        if once: 
            #~ ans.show()
            return None
        else: return nslookup(domain, ns_server, qtype, timeout, True)


def get_host(packet_load):
        #Gets the host a POST html packet was sent to.
        pos1 = packet_load.find("Host: ")
        if pos1 != -1:
            pos2 = packet_load.find("\r", pos1)
            result = unquote(packet_load[pos1+6:pos2])
            return result
        return None

        
def get_subhost(packet_load):
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
    #Gets all the relevant data from a packet and returns it.
    load = packet["Raw"].load.decode("utf-8", "ignore")
    form_load = load[load.find("\r\n\r\n")+4:]
    form_load_parsed = parse_qs(form_load,errors="backslashreplace")
    
    data = {"ip source":packet["IP"].src, "host":get_host(load)+get_subhost(load)}
    
    # ~ print(load)
    if relevant_attributes == "*":
        for item in form_load_parsed.items():
            data[item[0]] = item[1][0]
    else:
        for attribute in relevant_attributes:
            possible_value = form_load_parsed.get(attribute)#get_attribute_from_packet_load(attribute, load)
            if possible_value:
                data[attribute] = possible_value[0]
    return data
