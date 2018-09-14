'''
Created on Apr 3, 2018

@author: cloud
'''
import logging
from jinja2 import Template;
from exception import HttpResponseException,HttpRequestException

logger = logging.getLogger(__name__)

VALID_FIELDS={
    "http_version":["HTTP/1.1", "HTTP/1.0", "HTTP/0.9"],
    "response_code":{
        100:"Continue",
        101:"Switching Protocols",
        200:"OK",
        201:"Created",
        202:"Accepted",
        203:"Non-Authoritative Information",
        204:"No Content",
        205:"Reset Content",
        206:"Partial Content",
        300:"Multiple Choices",
        301:"Moved Permanently",
        302:"Found",
        303:"See Other",
        304:"Not Modified",
        305:"Use Proxy",
        306:"Unused",
        307:"Temporary Redirect",
        400:"Bad Request",
        401:"Unauthorized",
        402:"Payment Required",
        403:"Forbidden",
        404:"Not Found",
        405:"Method Not Allowed",
        406:"Not Acceptable",
        407:"Proxy Authentication Required",
        408:"Request Time-out",
        409:"Conflict",
        410:"Gone",
        411:"Length Required",
        412:"Precondition Failed",
        413:"Request Entity Too Large",
        414:"Request-URI Too Large",
        415:"Unsupported Media Type",
        416:"Requested range not satisfiable",
        417:"Expectation Failed",
        500:"Internal Server Error",
        501:"Not Implemented",
        502:"Bad Gateway",
        503:"Service Unavailable",
        504:"Gateway Time-out",
        505:"HTTP Version not supported"
        },
    "response_header_keys":[
        "Allow","Content-Encoding","Content-Length","Content-Type","Date",
        "Expires","Last-Modified","Location","Refresh","Server","Set-Cookie",
        "WWW-Authenticate"
        ],
    "request_mode":["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"],
    "request_header_keys":[
        "Accept","Accept-Charset","Accept-Encoding","Accept-Language",
        "Accept-Ranges","Authorization","Cache-Control","Connection",
        "Cookie","Content-Length","Content-Type","Date",
        "Expect","From","Host","If-Match",
        "If-Modified-Since","If-None-Match","If-Range","If-Unmodified-Since",
        "Max-Forwards","Pragma","Proxy-Authorization","Range",
        "Referer","TE","Upgrade","User-Agent",
        "Via","Warning"
        ]
    }

class HttpResponse():
    '''Http response object'''
    __slots__=("logger","__version","__response_code","__headers","__content","__rep_template")
    def __init__(self):
        self.logger = logger.getChild('HttpResponse {}'.format(id(self)))
        self.__version = 'HTTP/1.1'
        self.__response_code = 200
        self.__headers = dict()
        self.__content = ''
        _structure = '{{http_version}} {{response_code}}{{headers}}{{http_content}}'
        self.__rep_template = Template(_structure)
    
    def setHttpVersion(self,http_version):
        if http_version in  VALID_FIELDS["http_version"]:
            self.__version = http_version
        elif type(http_version) != str:
            raise TypeError("Invalid http version type. It should be string type.")
        else:
            raise HttpResponseException('Invalid HTTP version: %s,only supports [ "HTTP/1.1", "HTTP/1.0", "HTTP/0.9" ]'%http_version)
    
    def setRepCode(self,response_code):
        if response_code in VALID_FIELDS["response_code"].keys():
            self.__response_code = response_code
        elif type(response_code) != int:
            raise TypeError("Invalid http http response code type. It should be int type.")
        else:
            raise HttpResponseException("Invalid HTTP response code: %s.\n\
            100: Continue\n\
            101: Switching Protocols\n\
            200: OK\n\
            201: Created\n\
            202: Accepted\n\
            203: Non-Authoritative Information\n\
            204: No Content\n\
            205: Reset Content\n\
            206: Partial Content\n\
            300: Multiple Choices\n\
            301: Moved Permanently\n\
            302: Found\n\
            303: See Other\n\
            304: Not Modified\n\
            305: Use Proxy\n\
            306: Unused\n\
            307: Temporary Redirect\n\
            400: Bad Request\n\
            401: Unauthorized\n\
            402: Payment Required\n\
            403: Forbidden\n\
            404: Not Found\n\
            405: Method Not Allowed\n\
            406: Not Acceptable\n\
            407: Proxy Authentication Required\n\
            408: Request Time-out\n\
            409: Conflict\n\
            410: Gone\n\
            411: Length Required\n\
            412: Precondition Failed\n\
            413: Request Entity Too Large\n\
            414: Request-URI Too Large\n\
            415: Unsupported Media Type\n\
            416: Requested range not satisfiable\n\
            417: Expectation Failed\n\
            500: Internal Server Error\n\
            501: Not Implemented\n\
            502: Bad Gateway\n\
            503: Service Unavailable\n\
            504: Gateway Time-out\n\
            505: HTTP Version not supported\n\
            ")
    
    def setHeader(self,key,value):
        if key in VALID_FIELDS["response_header_keys"]:
            self.__headers[key] = value
        else:
            self.logger.warning("Invalid header: key = '%s' value = '%s'"%(key,value))
    
    def setHeaders(self,headers):
        if type(headers) == dict:
            for header_key in headers:
                self.setHeader(header_key, headers[header_key])
            self.__headers
        else:
            raise TypeError("Invalid http header type. It should be dictionary type.")
    
    def setContent(self,content):
        if type(content) == str:
            self.__content = content
        else:
            raise TypeError("Invalid http content type. It should be string type.")
    
    def setAll(self,http_version,response_code,headers,content):
        self.setHttpVersion(http_version)
        self.setRepCode(response_code)
        self.setHeaders(headers)
        self.setContent(content)
    
    def __headers2string(self):
        string_headers='\r\n'
        if self.__headers:
            for header_key in self.__headers:
                string_headers += "%s: %s\r\n"%(header_key,self.__headers[header_key])
        else:
            string_headers+='\r\n'
        return string_headers+'\r\n'

    def getfields(self):
        self.__headers["Content-Length"] = len(bytes(self.__content,'utf-8'))
        response = self.__rep_template.render(
            http_version = self.__version,
            response_code = "%s %s"%(self.__response_code,VALID_FIELDS["response_code"][self.__response_code]),
            headers = self.__headers2string(),
            http_content= self.__content
            )
        return bytes(response,'utf-8')
    
    def getBytes(self):
        return self.getfields()

class HttpRequest():
    '''Http request object'''
    __slots__=("logger","__req_mode","__req_url","__version","__headers","__data","__req_template")
    def __init__(self):
        self.logger = logger.getChild('HttpRequest {}'.format(id(self)))
        self.__req_mode = 'GET'
        self.__req_url = '/'
        self.__version = 'HTTP/1.1'
        self.__headers = dict()
        self.__data = ''
        _struture = '{{req_mode}} {{req_url}} {{version}}{{headers}}{{data}}'
        self.__req_template = Template(_struture)
    
    def setReqMode(self,request_mode):
        if request_mode in VALID_FIELDS["request_mode"]:
            self.__req_mode = request_mode
        elif type(request_mode) != str:
            raise TypeError("Invalid http request mode type. It should be string type.")
        else:
            raise HttpRequestException('Invalid request mode: %s. Only supports ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"]'%request_mode)
    
    def setReqUrl(self,request_url):
        if type(request_url) == str:
            self.__req_url = request_url
        else:
            raise TypeError("Invalid request url type. It should be string type.")
    
    def setHttpVersion(self,http_version):
        if type(http_version) != str:
            raise TypeError("Invalid request url type. It should be string type.")
        elif http_version in VALID_FIELDS["http_version"]:
            self.__version = http_version
        else:
            raise HttpResponseException('Invalid HTTP version: %s,only supports [ "HTTP/1.1", "HTTP/1.0", "HTTP/0.9" ]'%http_version)
    
    def setHeader(self,key,value):
        if key in VALID_FIELDS["request_header_keys"]:
            self.__headers[key] = value
        else:
            self.logger.warning("Invalid header: key = '%s' value = '%s'"%(key,value))
    
    def setHeaders(self,headers):
        if type(headers) == dict:
            for header_key in headers:
                self.setHeader(header_key, headers[header_key])
        else:
            raise TypeError("Invalid http header type. It should be dictionary type.")
    
    def setData(self,data):
        if type(data) == str:
            self.__data = data
        else:
            raise TypeError("Invalid request data type. It should be string type.")
    
    def setAll(self,request_mode,request_url,http_version,headers,data):
        self.setReqMode(request_mode)
        self.setReqUrl(request_url)
        self.setHttpVersion(http_version)
        self.setHeaders(headers)
        self.setData(data)
    
    def __headers2string(self):
        string_headers='\r\n'
        if self.__headers:
            for header_key in self.__headers:
                string_headers += "%s: %s\r\n"%(header_key,self.__headers[header_key])
        else:
            string_headers+='\r\n'
        return string_headers+'\r\n'
    
    def getFields(self):
        self.__headers["Content-Length"] = len(bytes(self.__data,'utf-8'))
        req = self.__req_template.render(
            req_mode = self.__req_mode,
            req_url = self.__req_url,
            version = self.__version,
            headers = self.__headers2string(),
            data = self.__data
            )
        return bytes(req,'utf-8')
    
    def getBytes(self):
        return self.getFields()
if __name__ == "__main__":
    pass

