import time,random
from fields.pcapfield import Ipcap,PcapHeader,Ipacket,PacketHeader\
,LinkLayerHeader,NetworkLayerHeader,UdpHeader,PdxpHeader,IgmpHeader
import tools

strip2int = lambda strip:sum([256**j*int(i) for j,i in enumerate(strip.split(".")[::-1])])

class IpProtocol():
    ICMP = 1
    IGMP = 2
    TCP  = 6
    UDP  = 17
    IPV6 = 41

class LinkType():
    # internet protocol
    INTERNET = 0x0800
    # X.75 internet
    X_75 = 0x0801
    # X.25 internet
    X_25 = 0x0805

class PcapHeaderFields():
    MAGIC = 0xd4c3b2a1
    MAJOR_VERSION = 2
    MINOR_VERSION = 4

def pdxp_header(version=1,src_addr=11,dest_addr=22,identification=1,serial_number=2,data_identification=6):
    header = PdxpHeader()
    header.version = version
    header.src_addr = src_addr
    header.dest_addr = dest_addr
    header.identification = identification
    header.serial_number = serial_number
    header.data_identification = data_identification
    current_time = time.time()
    header.send_date = int(current_time)
    header.send_time = int(current_time)%86400

    return header

def udp_header(dest_port=20,src_port=5801,data=b''):
    header = UdpHeader()
    header.dest_port = dest_port if dest_port else tools.random_int_port()
    header.src_port = src_port if src_port else tools.random_int_port()
    header.header_length = header.length + len(data)
    header.checksum = random.randint(1,65535)
    
    return header

def igmp_header(reserver=0):
    header = IgmpHeader()
    header.reserver = reserver
    header.checksum = random.randint(1,65535)
    header.multicat_ip = random.randint(strip2int("224.0.1.0"),strip2int("238.255.255.255"))
    
    return header
    
def ip_header(identification=1,flag=0,offset=0,protocol=IpProtocol.UDP,src_ip=None,dest_ip=None,data=b''):
    header = NetworkLayerHeader()
    if not isinstance(data, bytes):
        raise TypeError("'data' must be a bytes type.")
    header.total_length = header.length + len(data)
    header.identification = identification
    if offset%8 !=0:
        raise ValueError("\"offset\" must be a multiple of eight.")
    header.flag_segment = (flag<<13) + (offset>>3)#(flag<<13) + (offset*8 >> 3)
    header.time_to_live = 60
    header.checksum = random.randint(1,65535)
    header.protocol = protocol
    header.src_ip = src_ip if src_ip else tools.random_string_ip()
    header.dest_ip = dest_ip if dest_ip else tools.random_string_ip()
    
    return header

def link_layer_header(src_mac='2a:6c:bf:0f:a6:a8',dest_mac='2a:6c:bb:0f:d6:a7',link_type=LinkType.INTERNET):
    header = LinkLayerHeader()
    header.link_type = link_type
    header.dest_mac = dest_mac if dest_mac else tools.random_string_mac()
    header.src_mac = src_mac if src_mac else tools.random_string_mac()
    
    return header

def packet(link_header,network_header,transport_layer_header=None,application_header=None,data=None):
    ipacket = Ipacket()
    if data:
        ipacket.data = data
    if application_header:
        ipacket.application_layer_header = application_header
    if transport_layer_header:
        ipacket.transport_layer_header = transport_layer_header
    ipacket.networklayer_header = network_header
    ipacket.linklayer_header = link_header
    
    return ipacket

def packet_header(data_packet):
    header = PacketHeader()
    header.gmc_time = int(time.time())
    header.micro_time = 21
    header.actual_len = data_packet.length
    header.packet_len = data_packet.length

    return header

def pcap_header(time_zone=0,sigfigs=0,snaplen=65535,link_type=1):
    header = PcapHeader()
    header.magic = PcapHeaderFields.MAGIC
    header.major_version = PcapHeaderFields.MAJOR_VERSION
    header.minor_version = PcapHeaderFields.MINOR_VERSION
    header.time_zone = time_zone
    header.sigfigs = sigfigs
    header.snaplen = snaplen
    header.link_type = link_type
    
    return header

if __name__ == "__main__":
    pass
    