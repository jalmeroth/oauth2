#!/usr/bin/python
import json
import logging
logger = logging.getLogger(__name__)
from request import WebRequest


def shorten(longUrl, api_key = None):
    """Find documentation here: https://developers.google.com/url-shortener/v1/getting_started#shorten"""
    
    uri = 'https://www.googleapis.com/urlshortener/v1/url'
    
    params = {}
    if api_key:
        params['key'] = api_key
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    payload = {
        'longUrl': longUrl
    }
    
    r = WebRequest()
    result = r.post(uri, headers=headers, data=json.dumps(payload), params=params)
    data = r.json()
    
    return data.get('id')

def main():
    """docstring for main"""
    print shorten('http://almeroth.com')

if __name__ == '__main__':
    main()