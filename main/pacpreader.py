'''
Created on Apr 2, 2018

@author: cloud
'''
import struct
def main():
    fp = open("../readertest.pcap","rb+")
    m = fp.read(4)
    m = fp.read(2)
    m = fp.read(2)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    m = fp.read(4)
    r = fp.read(int(bytes(m).hex(),16))
    fp.close()
    print(int(bytes(m).hex(),16))
    print(r.decode("utf-8"))
    print(bytes(m).hex())
if __name__ == '__main__':
    main()