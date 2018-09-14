import os
from scapy.all import wrpcap

def save_packets(packets):
    #Saves the packets as a pcap file with a numeric name in 'packets' folder.
    
    #getting filename
    name = 1
    files = os.listdir("packets")
    while str(name) + ".pcap" in files:
        name += 1
    filename = "packets/" + str(name) + ".pcap"
    
    #writing to the filename
    wrpcap(filename, packets)
    os.system("chown " + os.getlogin() + ":" + os.getlogin() + " " + filename)
    
    return filename

def get_relevant_attributes_from_file(loc):
    #Reads the 'keywords' file and returns a list with every line. Each line is an
    #attribute that we are interested in.
    
    f = open(loc) #parece que en ubuntu el path del archivo principal se añade al path del archivo
    #importado, por lo que keywords puede estar en el mismo directorio que klesniffer.py
    result= [line.replace("\n", "") for line in f]
    f.close()
    return result


def parse_domains_and_ips(file_loc):
    #Reads the file and returns a dict with every domain we want to redirect and
    #the respective address we want to redirect it to.
    
    f = open(file_loc)
    result = {}
    for line in f:
        if not line.startswith("#") and line != "\n":
            line_splitted = line.replace("\n","").split(" ", 1)
            result[line_splitted[0]] = line_splitted[1]
    f.close()
    return result
        
