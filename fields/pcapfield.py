'''
Created on Apr 4, 2018

@author: cloud
'''
import struct,socket,re,ctypes
from exception import LengthError,PermissionDeniedError

class Ipcap(object):
    """pcap interface """
    __slots__ = ("__header","__content")
    def __init__(self,header):
        if not isinstance(header, PcapHeader):
            raise TypeError("'header' must be instance of PcapHeader")
        self.__header = header
        self.__content = b''
    
    def add_packet(self,packet_header,packet):
        if not  isinstance(packet_header, PacketHeader):
            raise TypeError
        if not isinstance(packet, Ipacket):
            raise TypeError
        self.__content = self.__content + packet_header.getBytes() + packet.getBytes()
    
    #return all pcap file content.
    def getBytes(self):
        return self.__header.getBytes() + self.__content
    
    def write_to_file(self,filename):
        if not isinstance(filename, str):
            raise TypeError("'filename' must be a string type.")
        with open(filename,"wb") as fopen:
            fopen.write(self.getBytes())
        
class Ipacket(object):
    """packet interface"""
    __slots__ = ("__linklayer_header","__networklayer_header","__transport_layer_header","__application_layer_header","__data")
    def __init__(self):
        self.__linklayer_header = b''
        self.__networklayer_header = b''
        self.__transport_layer_header = b''
        self.__application_layer_header = b''
        self.__data = b''
    
    @property
    def linklayer_header(self,linklayer_header):
        return self.__linklayer_header
    
    @linklayer_header.setter
    def linklayer_header(self,linklayer_header):
        if not isinstance(linklayer_header, LinkLayerHeader):
            raise TypeError
        self.__linklayer_header = linklayer_header
    
    @property
    def networklayer_header(self):
        return self.__networklayer_header
    
    @networklayer_header.setter
    def networklayer_header(self,networklayer_header):
        if not isinstance(networklayer_header, NetworkLayerHeader):
            raise TypeError
        self.__networklayer_header = networklayer_header
    
    @property
    def transport_layer_header(self):
        return self.__transport_layer_header
    
    @transport_layer_header.setter
    def transport_layer_header(self,transport_layer_header):
        if not isinstance(transport_layer_header, (UdpHeader,IgmpHeader)):
            raise TypeError
        self.__transport_layer_header = transport_layer_header
    
    @property
    def application_layer_header(self):
        return self.__application_layer_header
    
    @application_layer_header.setter
    def application_layer_header(self,application_layer_header):
        if not isinstance(application_layer_header, (PdxpHeader,)):
            raise TypeError
        self.__application_layer_header = application_layer_header
    
    @property
    def data(self):
        return self.__data
    
    @data.setter
    def data(self,data):
        if not isinstance(data, bytes):
            self.__data = data.encode('utf-8', errors='strict')
        else:
            self.__data = data
    
    @property
    def length(self):
        return len(self.getBytes())
    
    def getBytes(self):
        packet_bytes = self.__linklayer_header.getBytes() + self.__networklayer_header.getBytes()
        if self.__transport_layer_header:
            packet_bytes += self.__transport_layer_header.getBytes()
        if self.application_layer_header:
            packet_bytes += self.application_layer_header.getBytes()
        return packet_bytes + self.data
    
class PcapHeader(object):
    '''
    fields about pcap header.
    '''
    __slots__=("__struct","__magic","__major_version","__minor_version","__time_zone",\
               "__sigfigs","__snaplen","__link_type")
    def __init__(self):
        '''
        Constructor
        '''
#         self.__struct = struct.Struct("lhhiiii")
        # integer 32 bit
        self.__magic = b'\xa1\xb2\xc3\xd4'
        # short 16 bit 
        self.__major_version = None
        # short 16 bit
        self.__minor_version = None
        # integer 32 bit
        self.__time_zone = None
        # integer 32 bit
        self.__sigfigs = None
        # integer 32 bit
        self.__snaplen = None
        # integer 32 bit
        self.__link_type = None
        
    @property
    def magic(self):
        return self.__magic
    
    @magic.setter
    def magic(self,magic):
        self.__magic = struct.pack("!L", ctypes.c_ulong(magic).value)
        
    @property
    def major_version(self):
        return self.__major_version
    
    @major_version.setter
    def major_version(self,major_version):
        self.__major_version = struct.pack("H", ctypes.c_ushort(major_version).value)
    
    @property
    def minor_version(self):
        return self.__minor_version
    
    @minor_version.setter
    def minor_version(self,minor_version):
        self.__minor_version = struct.pack("H", ctypes.c_ushort(minor_version).value)
    
    @property
    def time_zone(self):
        return self.__time_zone
    
    @time_zone.setter
    def time_zone(self,time_zone):
        self.__time_zone = struct.pack("i", ctypes.c_int(time_zone).value)
    
    @property
    def sigfigs(self):
        return self.__sigfigs
    
    @sigfigs.setter
    def sigfigs(self,sigfigs):
        self.__sigfigs = struct.pack("i", ctypes.c_int(sigfigs).value)
    
    @property
    def snaplen(self):
        return self.__snaplen
    
    @snaplen.setter
    def snaplen(self,snaplen):
        self.__snaplen = struct.pack("i", ctypes.c_int(snaplen).value)
    
    @property
    def link_type(self):
        return self.__link_type
    
    @link_type.setter
    def link_type(self,link_type):
        self.__link_type = struct.pack("i", ctypes.c_int(link_type).value)
    
    def putAll(self,json_data):
        raise NotImplementedError
    
    def getBytes(self):
        return self.magic + self.major_version + self.minor_version + self.time_zone + self.sigfigs + self.snaplen + self.link_type

class PacketHeader(object):
    '''
    classdocs
    '''

    __slots__=("__struct","__gmc_time","__micro_time","__packet_len","__actual_len")
    def __init__(self):
        '''
        Constructor
        '''
#         self.__struct = struct.Struct("iiii")
        # integer 32 bit
        self.__gmc_time = b''
        # integer 32 bit
        self.__micro_time = b''
        # integer 32 bit
        self.__packet_len = b''
        # integer 32 bit
        self.__actual_len = b''
    
    @property
    def gmc_time(self):
        return self.__gmc_time

    @gmc_time.setter
    def gmc_time(self,gmc_time):
        if not isinstance(gmc_time, int):
            raise TypeError("PacketHeader.gmc_time must be a integer.")
        self.__gmc_time = struct.pack("i", ctypes.c_int(gmc_time).value)
    
    @property
    def micro_time(self):
        return self.__micro_time

    @micro_time.setter
    def micro_time(self,micro_time):
        if not isinstance(micro_time, int):
            raise TypeError("PacketHeader.micro_time must be a integer.")
        self.__micro_time = struct.pack("i", ctypes.c_int(micro_time).value)

    @property
    def packet_len(self):
        return self.__packet_len

    @packet_len.setter
    def packet_len(self,packet_len):
        if not isinstance(packet_len, int):
            raise TypeError("PacketHeader.packet_len must be a integer.")
        self.__packet_len = struct.pack("i", ctypes.c_int(packet_len).value)

    @property
    def actual_len(self):
        return self.__actual_len

    @actual_len.setter
    def actual_len(self,actual_len):
        if not isinstance(actual_len, int):
            raise TypeError("PacketHeader.actual_len must be a integer.")
        self.__actual_len = struct.pack("i", ctypes.c_int(actual_len).value)
        
    @property
    def length(self):
        return 16
    
    def putAll(self,data_dict):
        raise NotImplementedError
    
    def getBytes(self):
#         print((self.gmc_time,self.micro_time,self.packet_len,self.actual_len))
        return self.gmc_time + self.micro_time + self.packet_len + self.actual_len
    
class LinkLayerHeader(object):
    '''
    classdocs
    '''

    __slots__=("__struct","__dest_mac","__src_mac","__link_type")
    def __init__(self):
        '''
        Constructor
        '''
#         self.__struct = struct.Struct("6B6B!h")
        # char 48 bit
        self.__dest_mac = b'\x2a\x6c\xbf\x0f\xd6\xa7'
        # char 48 bit
        self.__src_mac = b'\x2a\x6c\xbf\x0f\xd6\xa8'
        # short 16 bit
        self.__link_type = b''
    
    def hex_str2int(self,mac):
        if isinstance(mac, int):
            return mac
        else:
            return int(mac,16)
    
    @property
    def dest_mac(self):
        return self.__dest_mac
    
    @dest_mac.setter
    def dest_mac(self,dest_mac):
        mac = self.mac_check(dest_mac, "dest mac adress")
        self.__dest_mac = struct.pack("6B", *mac)
    
    @property
    def src_mac(self):
        return self.__src_mac

    @src_mac.setter
    def src_mac(self,src_mac):
        mac = self.mac_check(src_mac, "source mac adress")
        self.__src_mac = struct.pack("6B", *mac)

    @property
    def link_type(self):
        return self.__link_type

    @link_type.setter
    def link_type(self,link_type):
        self.__link_type = struct.pack("!h", ctypes.c_short(link_type).value)
    
    @property
    def length(self):
        return 14
    
    def mac_check(self,mac,name):
        if isinstance(mac, str):
            return self.__string_mac_check(mac)
        elif isinstance(mac, tuple):
            self.__tuple_mac_check(mac, name)
            return mac
        else:
            raise TypeError("'%s' must be tuple type or string type."%name)
        
    def __tuple_mac_check(self,mac,name):
        if len(mac) !=6:
            raise LengthError("'%s' must be have six integer (1-255) or string of hex elements."%name)
        elif False in [self.__small_mac_check(ele) for ele in mac]:
            raise ValueError("'%s' must be have six integer (1-255) or string of hex elements."%name)
        
    def __string_mac_check(self,mac):
        if not re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$', mac):
            raise ValueError("'%s' is invalid mac address"%mac)
        else:
            return tuple([int(ele,16) for ele in re.split(r":", mac)])
        
    def __small_mac_check(self,mac):
        # is integer
        if isinstance(mac, int):
            if mac<256 and mac>0:
                return True
            else:
                return False
            
    def putAll(self,data_dict):
        raise NotImplementedError
    
    def getBytes(self):
        return self.dest_mac + self.src_mac + self.link_type

class NetworkLayerHeader():
    """network interface"""
    __slots__=("__struct","__version","__header_length",\
               "__version_header_length","__service_field",\
               "__total_length","__identification",\
               "__flag_segment","__time_to_live",\
               "__protocol","__checksum",\
               "__src_ip","__dest_ip"
               )
    def __init__(self):
#         self.__struct = struct.Struct("BB!HHHBBHII")
        # char 4 bit
        self.__version = 4
        # char 4 bit
        self.__header_length = 20
        # char version 4bit ,header length 4bit
        self.__version_header_length = b'\x45'
        # char 8 bit 
        self.__service_field = b'\x00'
        # unsigned short 16 bit
        self.__total_length = b''
        # unsigned short 16 bit
        self.__identification = b''
        # unsigned short 16 bit
        self.__flag_segment = b''
        # char 8 bit
        self.__time_to_live = b''
        # char 8 bit
        self.__protocol = b'\x11'
        # unsigned short 16 bit
        self.__checksum = b''
        # unsigned integer 32 bit
        self.__src_ip = b''
        # unsigned integer 32 bit
        self.__dest_ip = b''
    
    @property    
    def version(self):
        return self.__version
    
    @version.setter
    def version(self,version):
        self.__version = version
    
    @property    
    def header_length(self):
        return self.__header_length
    
    @header_length.setter
    def header_length(self,header_length):
        self.__header_length = header_length
    
    @property    
    def version_header_length(self):
        return self.__version_header_length
#         return struct.pack("c", self.version << 4 + self.header_length)
    
    @property
    def service_field(self):
        return self.__service_field
    
    @service_field.setter
    def service_field(self,service_field):
        self.__service_field = service_field
    
    @property
    def total_length(self):
        return self.__total_length
    
    @total_length.setter
    def total_length(self,total_length):
        self.__total_length = struct.pack("!H",ctypes.c_ushort(total_length).value)
    
    @property
    def identification(self):
        return self.__identification
    
    @identification.setter
    def identification(self,identification):
        self.__identification = struct.pack("!H",ctypes.c_ushort(identification).value)
    
    @property
    def flag_segment(self):
        return self.__flag_segment
    
    @flag_segment.setter
    def flag_segment(self,flag_segment):
        self.__flag_segment = struct.pack("!H",ctypes.c_ushort(flag_segment).value)
    
    @property
    def time_to_live(self):
        return self.__time_to_live
    
    @time_to_live.setter
    def time_to_live(self,time_to_live):
        self.__time_to_live = struct.pack("!B",ctypes.c_uint8(time_to_live).value)
    
    @property
    def protocol(self):
        return self.__protocol
    
    @protocol.setter
    def protocol(self,protocol):
        self.__protocol = struct.pack("!B",ctypes.c_uint8(protocol).value)
    
    @property
    def checksum(self):
        return self.__checksum
    
    @checksum.setter
    def checksum(self,checksum):
        self.__checksum = struct.pack("!H",ctypes.c_ushort(checksum).value)
    
    @property
    def src_ip(self):
        return self.__src_ip
    
    @src_ip.setter
    def src_ip(self,src_ip):
        self.__src_ip = socket.inet_aton(src_ip)
#         self.__src_ip = struct.pack("I",src_ip)
    
    @property
    def dest_ip(self):
        return self.__dest_ip
    
    @dest_ip.setter
    def dest_ip(self,dest_ip):
        self.__dest_ip = socket.inet_aton(dest_ip)
#         self.__dest_ip = struct.pack("I",dest_ip)
    
    @property
    def length(self):
        return 20
    
    def putAll(self):
        raise NotImplementedError
    
    def getBytes(self):
        return self.version_header_length + \
            self.service_field + \
            self.total_length + \
            self.identification + \
            self.flag_segment + \
            self.time_to_live + \
            self.protocol + \
            self.checksum + \
            self.src_ip + \
            self.dest_ip\
                                    
class IgmpHeader():
    """header of igmp"""
    def __init__(self):
        # unsigned char 8bit
        self.__version_type = b'\x12'
        # unsigned char 8bit
        self.__reserver = b''
        # unsigned short 16bit
        self.__checksum = b''
        # unsigned short 16bit
        self.__multicat_ip = b''
    
    @property
    def version_type(self):
        return self.__version_type
    
    @version_type.setter
    def version_type(self,version_type):
        self.__version_type = struct.pack("B",ctypes.c_uint8(version_type).value)
    
    @property
    def reserver(self):
        return self.__reserver
    
    @reserver.setter
    def reserver(self,reserver):
        self.__reserver = struct.pack("B",ctypes.c_int8(reserver).value)

    @property
    def checksum(self):
        return self.__checksum
    
    @checksum.setter
    def checksum(self,checksum):
        self.__checksum = struct.pack("!H",ctypes.c_ushort(checksum).value)
    
    @property
    def multicat_ip(self):
        return self.__multicat_ip
    
    @multicat_ip.setter
    def multicat_ip(self,multicat_ip):
        self.__multicat_ip = struct.pack("!I",ctypes.c_uint(multicat_ip).value)
    
    @property
    def length(self):
        return 6
    
    def putAll(self):
        raise NotImplementedError
    
    def getBytes(self):
        return self.version_type + self.reserver + self.checksum + self.multicat_ip
    
class UdpHeader():
    """header of udp protocol"""
    __slots__=("__struct","__src_port","__dest_port","__header_length","__checksum")
    def __init__(self):
#         self.__struct = struct.Struct("!H!H!HH")
        # src_port unsigned short 16 bit ;
        self.__src_port = b''
        # dest_port unsigned short 16 bit ;
        self.__dest_port = b''
        # length unsigned short 16 bit ;
        self.__header_length = b''
        # checksum unsigned short 16 bit
        self.__checksum = b''
        
    @property
    def src_port(self):
        return self.__src_port
    
    @src_port.setter
    def src_port(self,src_port):
        self.__src_port = struct.pack("!H",ctypes.c_ushort(src_port).value)
    
    @property
    def dest_port(self):
        return self.__dest_port
    
    @dest_port.setter
    def dest_port(self,dest_port):
        self.__dest_port = struct.pack("!H",ctypes.c_ushort(dest_port).value)
    
    @property
    def header_length(self):
        return self.__header_length
    
    @header_length.setter
    def header_length(self,header_length):
        self.__header_length = struct.pack("!H",ctypes.c_ushort(header_length).value)
    
    @property
    def checksum(self):
        return self.__checksum
    
    @checksum.setter
    def checksum(self,checksum):
        self.__checksum = struct.pack("!H",ctypes.c_ushort(checksum).value)
    
    @property
    def length(self):
        return 8
     
    def putAll(self):
        raise NotImplementedError
    
    def getBytes(self):
        return self.src_port + self.dest_port + self.header_length + self.checksum
    
class PdxpHeader():
    """"""
    __slots__ = ("__struct","__version","__src_addr","__dest_addr","__identification","__serial_number","__data_identification","__keep_field","__send_date","__send_time")
    def __init__(self):
#         self.__struct = struct.Struct("IIIIIIIII")
        # unsigned integer 32 bit
        self.__version = b''
        # unsigned integer 32 bit
        self.__src_addr = b''
        # unsigned integer 32 bit
        self.__dest_addr = b''
        # unsigned integer 32 bit
        self.__identification = b''
        # unsigned integer 32 bit
        self.__serial_number = b''
        # unsigned integer 32 bit
        self.__data_identification = b''
        # unsigned integer 32 bit
        self.__keep_field = struct.pack("!I",0)
        # unsigned integer 32 bit
        self.__send_date = b''
        # unsigned integer 32 bit
        self.__send_time = b''
        
    @property
    def version(self):
        return self.__version
 
    @version.setter
    def version(self,version):
        self.__version = struct.pack("!I",ctypes.c_uint(version).value)
    
    @property
    def src_addr(self):
        return self.__src_addr
    
    @src_addr.setter
    def src_addr(self,source_address):
        self.__src_addr = struct.pack("!I",ctypes.c_uint(source_address).value)
    
    @property
    def dest_addr(self):
        return self.__dest_addr
    
    @dest_addr.setter
    def dest_addr(self,dest_address):
        self.__dest_addr = struct.pack("!I",ctypes.c_uint(dest_address).value)
    
    @property
    def identification(self):
        return self.__identification
    
    @identification.setter
    def identification(self,identification):
        self.__identification = struct.pack("!I",ctypes.c_uint(identification).value)
    
    @property
    def serial_number(self):
        return self.__serial_number

    @serial_number.setter
    def serial_number(self,serial_number):
        self.__serial_number = struct.pack("!I",ctypes.c_uint(serial_number).value)
    
    @property
    def data_identification(self):
        return self.__data_identification
    
    @data_identification.setter
    def data_identification(self,data_identification):
        self.__data_identification = struct.pack("!I",ctypes.c_uint(data_identification).value)
    
    @property
    def keep_field(self):
        return self.__keep_field
    
    @keep_field.setter
    def keep_field(self,keep_field):
        raise PermissionDeniedError("can't change PdxpHeader.keep_field")
    
    @property
    def send_date(self):
        return self.__send_date
    
    @send_date.setter
    def send_date(self,send_date):
        self.__send_date = struct.pack("!I",ctypes.c_uint(send_date).value)
    
    @property
    def send_time(self):
        return self.__send_time
    
    @send_time.setter
    def send_time(self,send_time):
        if not isinstance(send_time, int):
            raise TypeError("'send_time' must be integer type.")
        self.__send_time = struct.pack("!I",ctypes.c_uint(send_time).value)
    
    @property
    def length(self):
        return 36
    
    def putAll(self):
        raise NotImplementedError
    
    def getBytes(self):
        return self.version + \
            self.src_addr + \
            self.dest_addr + \
            self.identification + \
            self.serial_number + \
            self.data_identification + \
            self.keep_field + \
            self.send_date + \
            self.send_time
    
if __name__ == "__main__":
    pass
    
