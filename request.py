#!/usr/bin/python
import json
import urllib
import logging
logger = logging.getLogger(__name__)

HTTP_library = None

try:
    import requests
except ImportError as e:
    try:
        from google.appengine.api import urlfetch
    except ImportError as e:
        raise e
    else:
        HTTP_library = "urlfetch"
else:
    HTTP_library = "requests"

logger.debug("Using HTTP Library: " + HTTP_library)


class WebRequest(object):
    """docstring for WebRequest"""
    def __init__(self):
        super(WebRequest, self).__init__()
        self.http_library = HTTP_library
        self.request = None
    
    def queryString(self, url, params):
        """converts a dict of params into a query string of url"""
        sep = "?"
        # if url has a query string already, use ampersand as sep
        if url.find(sep) > -1:
            sep = "&"
        # convert params into query string
        url += sep + urllib.urlencode(params)
        return url
    
    def makeRequestWithUrlfetch(self, url, **kwargs):
        """docstring for makeRequestWithUrlfetch"""
        method = kwargs.pop('method', 'GET')
        
        # TODO implement json-type data payloads
        
        payload = kwargs.pop('data', {})
        if isinstance(payload, dict):
            payload = urllib.urlencode(payload)
        
        # if params where given, convert them into query string
        params = kwargs.pop('params', None)
        if params:
            url = self.queryString(url, params)
        
        return urlfetch.fetch(url=url, method=method, payload=payload, **kwargs)
    
    def makeRequestWithRequests(self, url, **kwargs):
        """docstring for makeRequestWithRequests"""
        method = kwargs.pop('method', 'GET')
        kwargs.pop('deadline', None)
        logger.info('method:' + method)
        logger.info('kwargs:' + str(kwargs))
        return requests.request(method, url, **kwargs)
    
    def req(self, url, **kwargs):
        """docstring for req"""
        if HTTP_library == "requests":
            self.request = self.makeRequestWithRequests(url, **kwargs)
        elif HTTP_library == "urlfetch":
            self.request = self.makeRequestWithUrlfetch(url, **kwargs)
        else:
            pass
        return self
    
    def get(self, url, **kwargs):
        """docstring for get"""
        kwargs['method'] = "GET"
        return self.req(url, **kwargs)
    
    def post(self, url, **kwargs):
        """docstring for post"""
        kwargs['method'] = "POST"
        return self.req(url, **kwargs)
    
    def json(self):
        """docstring for json"""
        if HTTP_library == "requests":
            return self.request.json()
        elif HTTP_library == "urlfetch":
            return json.loads(self.text)
        else:
            pass
    
    @property
    def text(self):
        """docstring for text"""
        if HTTP_library == "requests":
            return self.request.text
        elif HTTP_library == "urlfetch":
            return self.request.content
        else:
            pass
    
    @property
    def status_code(self):
        """docstring for text"""
        if HTTP_library == "requests":
            return self.request.status_code
        elif HTTP_library == "urlfetch":
            return self.request.status_code
        else:
            pass
    
    @property
    def ok(self):
        """docstring for ok"""
        ok_codes = (200, 201, 207)
        return self.status_code in ok_codes

def main():
    """docstring for main"""
    pass

if __name__ == '__main__':
    main()