#!/usr/bin/python
import os
import json
import logging
logger = logging.getLogger(__name__)
from request import WebRequest


def work_dir(path = '../'):
    """docstring for _work_dir"""
    return os.path.dirname(os.path.realpath(os.path.join(__file__, path)))

def save(data, filename):
    """docstring for save"""
    file = os.path.join(work_dir(), filename)
    
    if not os.path.exists(os.path.dirname(file)):
        os.makedirs(os.path.dirname(file))
    
    with open(file, "w+") as jsonFile:
        json.dump(data, jsonFile)

def load(filename):
    """docstring for load"""
    file = os.path.join(work_dir(), filename)
    
    if os.path.exists(file):
        with open(file,"r") as jsonFile:
            return json.load(jsonFile)
    else:
        return {}

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