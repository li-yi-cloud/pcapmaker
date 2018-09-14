import time,random
import fields
from io import BytesIO
from _functools import reduce
from fields.pcapfield import Ipcap
import struct

def ushort_checksum(data,byteoder="little"):
    if not isinstance(data, bytes):
        raise TypeError("'data' must be bytes type.")
    length = len(data)
    check_sum=0
    for i in range(0,length):
        check_sum += int.from_bytes(data[i:i+1],byteoder)
        check_sum &= 0xFFFF
    return check_sum

def data_slice(data,header_length,slice_length = 1480):
    bytes_data = b''
    if not isinstance(header_length, int):
        raise TypeError("header_length must bee integer type.")
    if header_length <0 or header_length >= 1480:
        raise ValueError("header_length must be in 0-1480")
    if isinstance(data, str):
        bytes_data = data.encode('utf-8', errors='strict')
    elif isinstance(data, bytes):
        bytes_data = data
    else:
        raise TypeError("Invalid data type. must be string or bytes.")
    if slice_length < 8 or slice_length > 1480 or slice_length%8 != 0:
        raise ValueError("Invalid slice_length ,must be in 1-1480 and integer multiple of eight ")
#     if header_length > slice_length:
#         raise  ValueError("header_length must small than slice_length")
    bytes_data = struct.pack("%sB"%header_length,*tuple([0 for _ in range(header_length)]))+bytes_data
    
    idata=BytesIO(bytes_data)
    slice_data = []
#     idata.read(header_length)
    offset = 0
    for _ in range(len(bytes_data)//slice_length):
        slice_data.append((idata.read(slice_length),offset))
        offset+=slice_length
    if len(bytes_data)%slice_length != 0:
        slice_data.append((idata.read(),offset))
    if header_length >= slice_length:
        for _ in range(int(header_length/slice_length)):
            slice_data.pop(0)
        if header_length%slice_length !=0:
            slice_data[0]=(slice_data[0][0][header_length%slice_length:],slice_data[0][1])
    else:
        slice_data[0]=(slice_data[0][0][header_length:],slice_data[0][1])
    idata.close()
    
    return slice_data

def random_string_mac():
    valid_mac = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    return reduce(lambda x,y: x+":"+y,[random.choice(valid_mac)+random.choice(valid_mac) for _ in range(6)])

def random_string_ip():
    return "%s.%s.%s.%s"%tuple([random.randint(1,255) for _ in range(4)])

def random_int_port():
    return random.randint(1,65535)

def pcap_writer(filename,pcap):
    if not isinstance(filename, str):
        raise TypeError("'filename' must be a string type.")
    if not isinstance(pcap, Ipcap):
        raise TypeError("'pcap' must be a Ipcap instance.")
    with open(filename,"wb") as fopen:
        fopen.write(pcap.getBytes())
        
if __name__ == "__main__":
    pass
