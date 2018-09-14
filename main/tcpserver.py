'''
Created on Apr 2, 2018

@author: cloud
'''
import socketserver
import codecs,os,sys
from yaml import load

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.chdir(BASE_DIR)

from fields.httpfield import HttpResponse

class serverconfig():
    def __init__(self,yaml_config_file):
        self._yaml_config_file = yaml_config_file
        self.__config = {}
    
    def read(self):
        with open(self._yaml_config_file,'r') as config_open:
            self.__config = load(config_open.read())
        return self
    
    def __getitem__(self,key):
        return self.__config[key]
    
    def __setitem__(self,key,value):
        self.__config[key]=value

def read_file(filename):
    with codecs.open(filename,'r','utf-8') as fopen:
        return fopen.read()
    
class tcphandler(socketserver.BaseRequestHandler):
    response = HttpResponse()
    def handle(self):
        self.data = self.request.recv(1024).strip()
#         print(self.data)
        if os.getenv("Prototype", "tcp") == "http":
            response_content = serverconfig("config/httpresponse.yaml").read()
            self.response.setAll(response_content["version"], response_content["response_code"], response_content["headers"], response_content["content"]) 
            self.request.sendall(self.response.getfields())
            print("Success")
        elif os.getenv("Prototype", "tcp") == "tcp":
            rsp = read_file("config/tcpresponse.txt")
            self.request.sendall(bytes(rsp,'utf-8'))
        
if __name__=="__main__":
    os.environ["Prototype"]="tcp"
    server = socketserver.TCPServer(("0.0.0.0",9021),tcphandler)
    server.allow_reuse_address = True;
    server.serve_forever()
    
    
    
    