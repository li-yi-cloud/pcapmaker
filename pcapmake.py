'''
Created on Jun 7, 2018

@author: cloud
'''
import tools,fields
from fields.pcapfield import Ipcap

# create a pcap instance
pcap = Ipcap(fields.pcap_header())

# ==================
# slice 1
# ==================
# packet data
data="abcdefghi好"
# application layer header
pdxp_header = fields.pdxp_header()
# transport layer header
udp_header = fields.udp_header(dest_port=33, src_port=80, data=pdxp_header.getBytes() + data.encode(encoding='utf_8', errors='strict'))
# tcp/ip layer header
network_header = fields.ip_header(identification=2, flag=1, offset=0, src_ip="10.94.1.2", dest_ip="10.94.3.1", data = udp_header.getBytes() + pdxp_header.getBytes() + data.encode(encoding='utf_8', errors='strict'))
# link layer header
link_header = fields.link_layer_header()
# packet instance
packet = fields.packet(application_header=pdxp_header, transport_layer_header=udp_header, network_header=network_header, link_header=link_header, data=data)
# pcaket header
packet_header= fields.packet_header(packet)

# add packet header and packet to pcap instance.y
pcap.add_packet(packet_header, packet)

# ==================
# slice 2
# ==================
data_1="好cba01234567"
network_header_1 = fields.ip_header(identification=2, flag=1, offset=56, src_ip="10.94.1.2", dest_ip="10.94.3.1", data=data_1.encode(encoding='utf_8', errors='strict'))
link_header_1 = fields.link_layer_header()
packet_1 = fields.packet(network_header=network_header_1, link_header=link_header_1, data=data_1)
packet_header_1= fields.packet_header(packet_1)

pcap.add_packet(packet_header_1, packet_1)

# ==================
# slice 3
# ==================
network_header_1 = fields.ip_header(identification=2, flag=0, offset=64, protocol=fields.IpProtocol.UDP,src_ip="10.94.1.2", dest_ip="10.94.3.1", data=data_1.encode(encoding='utf_8', errors='strict'))
link_header_1 = fields.link_layer_header(src_mac=tools.random_string_mac(),dest_mac=tools.random_string_mac())
packet_1 = fields.packet(network_header=network_header_1, link_header=link_header_1, data=data_1)
packet_header_1= fields.packet_header(packet_1)


pcap.add_packet(packet_header_1, packet_1)

#=====================
#  ICMP packet
# ====================
icmp_header=fields.igmp_header(reserver=0)
icmp_ip_header = fields.ip_header(identification=2, flag=0, offset=0, protocol=fields.IpProtocol.IGMP, src_ip="10.94.1.4", dest_ip="10.94.3.5", data=icmp_header.getBytes())
icmp_link_header = fields.link_layer_header()
icmp_packet = fields.packet(link_header=icmp_link_header, network_header=icmp_ip_header,transport_layer_header=icmp_header)
icmp_packet_header = fields.packet_header(icmp_packet)


pcap.add_packet(icmp_packet_header,icmp_packet)

# write pcap instance to file.
tools.pcap_writer("test.pcap", pcap)

print(tools.random_string_mac())
print(tools.data_slice("========1234567890abcdefgdddddddd", header_length=0, slice_length=8))
