import os
from scapy.all import wrpcap

def save_packets(packets):
    """Saves packets as a pcap file with a numeric name in 'packets' folder."
    
    Parameters:
        packets (scapy.plist.PacketList): list of packets that will be saved.
    
    Returns:
        str: location of the saved file.
    """
    
    #getting filename
    name = 1
    
    try:
        files = os.listdir("packets")
    except FileNotFoundError:
        os.system("mkdir packets")
        os.system("chown " + os.getlogin() + ":" + os.getlogin() + " packets")
        files = []
        
    while str(name) + ".pcap" in files:
        name += 1
    filename = "packets/" + str(name) + ".pcap"
    
    #writing to the filename
    wrpcap(filename, packets)
    os.system("chown " + os.getlogin() + ":" + os.getlogin() + " " + filename)
    
    return filename


def get_lines_from_file(loc):
    """Reads the file and returns a list with every line.
    
    Parameters:
        loc (str): location of the file.
    
    Returns:
        list: list containing each of the lines of the file.
    """
    
    f = open(loc)
    result= [line.replace("\n", "") for line in f]
    f.close()
    return result


def parse_domains_and_ips(file_loc):
    """Reads the file and returns a dict with every domain we want to redirect 
    and the respective address we want to redirect it to.
    
    Parameters:
        file_loc (str): the location of the file.
        
    Returns:
        dict: a dictionary whose keys are the domains and whose values are the
            IP addresses or the domains that the key should be redirected to.
    """
    
    f = open(file_loc)
    result = {}
    for line in f:
        if not line.startswith("#") and line != "\n":
            line_splitted = line.replace("\n","").split(" ", 1)
            result[line_splitted[0]] = line_splitted[1]
    f.close()
    return result
        
