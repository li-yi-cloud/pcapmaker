'''
Created on Apr 2, 2018

@author: cloud
'''
import socket,sys,os
from yaml import load,Loader
from fields.httpfield import HttpRequest
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.chdir(BASE_DIR)

class clientconfig():
    def __init__(self,yaml_config_file):
        self._yaml_config_file = yaml_config_file
        self.__config = {}
    
    def read(self):
        with open(self._yaml_config_file,'r') as config_open:
            self.__config = load(config_open.read(),Loader = Loader)
        return self
    
    def __getitem__(self,key):
        return self.__config[key]
    
    def __setitem__(self,key,value):
        self.__config[key]=value
        
def run_client():
    req = HttpRequest()
    config = clientconfig("config/httprequest.yaml").read()
    req.setAll(request_mode = config["request_mode"], request_url=config["request_url"], http_version=config["http_version"], headers=config["headers"], data= config["data"])
    sc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sc.connect(("10.88.2.10",9021))
    sc.send(req.getFields())
    ret = sc.recv(1024)
    while len(ret):
        print(ret)
        ret = sc.recv(1024)
    sc.close()
    
if __name__ == "__main__":
    run_client()
    
    