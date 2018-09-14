'''
Created on Apr 2, 2018

@author: cloud
'''
import yaml,codecs,os,re
import tools,fields
from fields.pcapfield import Ipcap
import settings
from exception import ProtocolError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG = {}
with codecs.open("../config/ipcap.yaml", 'r', "utf-8") as config_open:
    CONFIG = yaml.load(stream=config_open)

PACKET_LIST = [i for i in CONFIG.keys() if re.match(r'^packet_[0-9]{1,}$', i)]

if "pcap_header" in CONFIG or CONFIG["pcap_header"] == None:
    pcap = Ipcap(fields.pcap_header())
else: 
    _header_args= {}
    for arg_key in settings.pcap_header:
        if arg_key in CONFIG["pcap_header"]:
            _header_args[arg_key] = CONFIG["pcap_header"][arg_key]
        else:
            _header_args[arg_key] = settings.pcap_header[arg_key]
    pcap = Ipcap(fields.pcap_header(**_header_args))

for packet_name in PACKET_LIST: 
    config= CONFIG[packet_name]
    
    # link layer
    link_layer_header_args = {}
    for key in settings.link_layer_header:
        if key in config["link_layer_header"]:
            link_layer_header_args[key] = config["link_layer_header"][key]
        else:
            link_layer_header_args[key] = settings.link_layer_header[key]
    link_layer_header = fields.link_layer_header(**link_layer_header_args)
    
    #udp
    if "udp_header" in config["transport_layer_header"]:
        data=''
        slice_length = settings.slice_length if "slice_length" not in config else config["slice_length"]
        with codecs.open(config["data_file"],"r","utf-8") as data_open:
            data = data_open.read()
        
        # application_layer
        # pdxp layer
        pdxp_header_args={}
        pdxp_header = fields.pdxp_header(**pdxp_header_args)
        # transform layer
        # udp layer
        udp_header_args={}
        for key in settings.udp_header:
            if key in config["transport_layer_header"]["udp_header"]:
                udp_header_args[key] = config["transport_layer_header"]["udp_header"][key]
            else:
                udp_header_args[key] = settings.udp_header[key]
        if slice_length < len(pdxp_header.getBytes()+data.encode(encoding='utf_8', errors='strict'))+8:
            udp_header_args["data"]=pdxp_header.getBytes()+tools.data_slice(data.encode(encoding='utf_8', errors='strict'), header_length=pdxp_header.length+8, slice_length=slice_length-20-14)[0][0]
        else:
            udp_header_args["data"]=pdxp_header.getBytes()+data.encode(encoding='utf_8', errors='strict')
        
        udp_header = fields.udp_header(**udp_header_args)
        # ip layer
        ip_header_args={}
        for key in settings.ip_layer_header:
            if key in config["ip_layer_header"]:
                ip_header_args[key] =  config["ip_layer_header"][key]
            else:
                ip_header_args[key] = settings.ip_layer_header[key]
        slices = tools.data_slice(data=udp_header.getBytes()+pdxp_header.getBytes()+data.encode(encoding='utf_8', errors='strict'), header_length=0, slice_length=slice_length-34)
        if len(slices)>1:
            ip_header_args["src_ip"] = ip_header_args["src_ip"] if ip_header_args["src_ip"] else tools.random_string_ip()
            ip_header_args["dest_ip"] = ip_header_args["dest_ip"] if ip_header_args["dest_ip"] else tools.random_string_ip()
        ip_layer_headers = []
        for index,ip_slice in enumerate(slices):
            slice_conf = ip_header_args
            slice_conf["flag"] = 1
            if index ==(len(slices)-1):
                slice_conf["flag"] = 0
            slice_conf["offset"]= ip_slice[1]
            slice_conf["protocol"] = fields.IpProtocol.UDP
            slice_conf["data"]=ip_slice[0]
            ip_layer_headers.append(fields.ip_header(**slice_conf))
        headers_packets=[]
        for index,ip_slice in enumerate(slices):
            packet = fields.packet(link_header=link_layer_header, network_header=ip_layer_headers[index], data=ip_slice[0])
            packet_header = fields.packet_header(packet)
            headers_packets.append((packet_header,packet))
        
        for header_packet in headers_packets:
            pcap.add_packet(*header_packet)
    elif "igmp_header" in config["transport_layer_header"]:
        # igmp layer header
        igmp_header_args = config["transport_layer_header"]["igmp_header"] if config["transport_layer_header"]["igmp_header"] else settings.igmp_header
        igmp_header = fields.igmp_header(**igmp_header_args)
        # ip layer header
        ip_header_args={}
        for key in settings.ip_layer_header:
            if key in config["ip_layer_header"]:
                ip_header_args[key] =  config["ip_layer_header"][key]
            else:
                ip_header_args[key] = settings.ip_layer_header[key]
        ip_header_args["data"]=igmp_header.getBytes()
        ip_header_args["protocol"]=fields.IpProtocol.IGMP
        ip_header = fields.ip_header(**ip_header_args)
        packet = fields.packet(link_header=link_layer_header, network_header=ip_header, transport_layer_header=igmp_header)
        packet_header = fields.packet_header(packet)
        pcap.add_packet(packet_header, packet)
    else:
        raise ProtocolError("unsupported protocol")
pcap.write_to_file('../test.pcap')
# tools.pcap_writer("../test.pcap", pcap)
if __name__ == '__main__':
    pass
