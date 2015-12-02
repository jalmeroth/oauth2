#!/usr/bin/python
import json
import time
import urllib
import logging
logger = logging.getLogger(__name__)

from request import WebRequest
from helpers import shorten


class Authenticator(object):
    """docstring for Authenticator"""
    def __init__(self, client_id, client_secret, scope, tokens = None):
        super(Authenticator, self).__init__()
        
        # we need to know who is authorized
        if not 'email' in scope:
            scope.append('email')
        
        self.prefs = {
            "access_type": "offline",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "tokens": {},
            "response_type": "code",
            "scope": " ".join(scope),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "info_uri": "https://www.googleapis.com/oauth2/v1/tokeninfo",
            "token_uri": "https://www.googleapis.com/oauth2/v3/token",
            "revoke_uri": "https://accounts.google.com/o/oauth2/revoke"
        }
        
        if tokens:
            self.tokens = tokens
    
    def authorize(self, user_Id = None):
        """ More info: https://developers.google.com/accounts/docs/OAuth2InstalledApp """
        tokens = self.tokens
        logger.debug("user_Id: " + str(user_Id))
        
        if user_Id in tokens:
            user_token = tokens.get(user_Id)
            if user_token:
                refresh_token = user_token.get('refresh_token')
                return self.refresh(refresh_token, user_Id)
        else:
            auth_uri = self.prefs.get('auth_uri')
            
            params = {
                "scope": self.prefs.get('scope'),
                "redirect_uri": self.prefs.get('redirect_uri'),
                "response_type": self.prefs.get('response_type'),
                "client_id": self.prefs.get('client_id'),
                "access_type": self.prefs.get('access_type')
            }
            
            longUri = auth_uri + "?" + urllib.urlencode(params)
            shortUri = shorten(longUri)
            
            print 10 * "=", "Authorizing account:", (user_Id if user_Id else "n/a")
            print "Go to the following link in your browser:", shortUri if shortUri else longUri
            
            code = raw_input("Enter verification code: ")
            data = self.exchange(code)
            
            access_token = data.get('access_token')
            refresh_token = data.get('refresh_token')
            
            return self.check_store_Token(user_Id, access_token, refresh_token)
    
    def check_store_Token(self, user_Id, access_token, refresh_token = None):
        """docstring for checkToken"""
        info = self.info(access_token)
        user_email = info.get('email')
        
        if user_email == user_Id:
            logger.info("Holding userToken for: " + user_email)
            userToken = self.tokens.get(user_Id, {})
            
            fiveMin = 5 * 60
            expires_in = int(info.get('expires_in', 0))
            timeNow = int(time.time())
            expires = timeNow + expires_in - fiveMin
            
            newToken = {
                "access_token": access_token,
                "expires": expires
            }
            if refresh_token:
                newToken["refresh_token"] = refresh_token
            
            # update to new values while preserving other existing key/values
            userToken.update(newToken)
            self.tokens[user_Id] = userToken
        else:
            logger.warning("User mismatch: you will have to re-authenticate next time.")
        
        return access_token
    
    def exchange(self, code):
        """docstring for exchange"""
        token_uri = self.prefs.get('token_uri')
        
        payload = {
            "code": code,
            "client_id": self.prefs.get('client_id'),
            "client_secret": self.prefs.get('client_secret'),
            "redirect_uri": self.prefs.get('redirect_uri'),
            "grant_type": "authorization_code"
        }
        
        r = WebRequest()
        result = r.post(token_uri, data=payload)
        
        if result.ok:
            return result.json()
    
    def refresh(self, token = None, user_Id = None):
        """docstring for refresh"""
        token_uri = self.prefs.get("token_uri")
        logger.debug("token: " + str(token))
        
        if not token:
            # need to authorize first
            return self.authorize(user_Id)
        else:
            payload = {
                "refresh_token": token,
                "client_id": self.prefs.get("client_id"),
                "client_secret": self.prefs.get("client_secret"),
                "grant_type": "refresh_token"
            }
            r = WebRequest()
            result = r.post(token_uri, data=payload)
            
            if result.ok:
                data = result.json()
                return self.check_store_Token(user_Id, data.get('access_token'))
            else:
                # removing token, prevents refreshing loops
                self.tokens.pop(user_Id, None)
                return self.authorize(user_Id)
    
    def info(self, token):
        """docstring for info"""
        info_uri = self.prefs.get("info_uri")
        
        params = {
            "access_token": token
        }
        
        r = WebRequest()
        result = r.get(info_uri, params=params)
        
        if result.ok:
            return result.json()
    
    def revoke(self, token):
        """docstring for revoke"""
        revoke_uri = self.prefs.get("revoke_uri")
        
        params = {
            "token": token
        }
        
        r = WebRequest()
        result = r.get(revoke_uri, params=params)
        
        if result.ok:
            return result
    
    def signedRequest(self, url, user_Id, **kwargs):
        """docstring for signedRequest"""
        
        signedHeader = {
            "Authorization": "Bearer " + str(self.Bearer(user_Id))
        }
        
        headers = kwargs.get('headers', {})
        headers.update(signedHeader)
        kwargs['headers'] = headers
        
        r = WebRequest()
        return r.req(url, **kwargs)
    
    def Bearer(self, user_Id):
        """docstring for Bearer"""
        tokens = self.tokens
        
        if user_Id in tokens:
            
            user_token = tokens.get(user_Id)
            expires = user_token.get('expires', 0)
            timeNow = int(time.time())
            
            if(expires > timeNow):
                logger.info('Bearer: Token is valid.')
                return user_token.get('access_token')
            else:
                logger.info('Bearer: Token expired.')
                return self.refresh(user_token.get('refresh_token'), user_Id)
            
        else:
            logger.info('Bearer: Token not found.')
            return self.authorize(user_Id)
    
    @property
    def tokens(self):
        """docstring for tokens"""
        return self.prefs.get('tokens', {}) # all existing tokens

    @tokens.setter
    def tokens(self, token):
        """docstring for tokens"""
        user_token = self.tokens
        user_token.update(token)
        self.prefs['tokens'] = user_token

def main():
    """docstring for main"""
    pass

if __name__ == '__main__':
    main()