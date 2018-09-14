'''
Created on Apr 2, 2018

@author: cloud
'''
import os,sys
from urllib3 import PoolManager,disable_warnings,exceptions
from yaml import load
from urllib3.response import HTTPResponse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.chdir(BASE_DIR)

class clientconfig():
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
        
def run_client():
    config = clientconfig("config/httprequest.yaml").read()
    disable_warnings(exceptions.HTTPWarning)
    http_client = PoolManager()

    r = http_client.request(config["request_mode"],config["headers"]["Referer"],None,config["headers"])
    print(r.data)

if __name__ == '__main__':
    run_client()

