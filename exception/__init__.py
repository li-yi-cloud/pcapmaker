
class OutofLengthException(Exception):
    '''The fields is out of the length.'''
    
class HttpResponseException(Exception):
    '''Invalid http response exception.'''

class HttpRequestException(Exception):
    '''Invalid http request exception.'''

class LengthError(Exception):
    """value length error"""

class ProtocolError(Exception):
    """Unsupported Protocol"""

class PermissionDeniedError(Exception):
    """Permission denied"""