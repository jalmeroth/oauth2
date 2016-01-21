#!/usr/bin/python
import json
import time
import urllib
import logging
import crypt as crypt
logger = logging.getLogger(__name__)

from request import WebRequest
from helpers import shorten


URI_AUTH = "https://accounts.google.com/o/oauth2/auth"
URI_INFO = "https://www.googleapis.com/oauth2/v1/tokeninfo"
URI_TOKEN = "https://www.googleapis.com/oauth2/v3/token"
URI_REVOKE = "https://accounts.google.com/o/oauth2/revoke"


class AuthBase(object):
    """docstring for AuthBase"""
    def __init__(self, **kwargs):
        super(AuthBase, self).__init__()
        
        # we need to know who is goint to be authorized
        scope = kwargs.get('scope', [])
        if not 'email' in scope:
            scope.append('email')
        
        logger.debug("scope %s", scope)
        
        self.tokens = kwargs.get('tokens', {})
        self.prefs = kwargs.get('prefs', {})
        
        self.prefs["scope"] = " ".join(scope)
        self.prefs["auth_uri"] = URI_AUTH
        self.prefs["info_uri"] = URI_INFO
        self.prefs["token_uri"] = URI_TOKEN
        self.prefs["revoke_uri"] = URI_REVOKE
    
    def authorize(self):
        """docstring for authorize"""
        raise NotImplementedError("Subclasses should implement this!")
    
    def refresh(self):
        """docstring for refresh"""
        raise NotImplementedError("Subclasses should implement this!")
    
    def check_store_Token(self, user_Id, data):
        """docstring for checkToken"""
        
        refresh_token = data.get('refresh_token')
        access_token = data.get('access_token')
        
        info = self.info(access_token)
        user_email = info.get('email')
        logger.debug('user_email: %s', user_email)
        
        # let the user decide, which account he uses on consent screen
        if user_Id is None:
            user_Id = user_email
        
        # warn if user chose, different account then requested
        if user_email != user_Id:
            logger.warning("User mismatch: you will have to re-authenticate next time.")
            
        existingToken = self.tokens.get(user_Id, {})
        
        #overwrite expires with actual time -5 min.
        fiveMin = 5 * 60
        expires_in = int(data.get('expires_in', 0))
        timeNow = int(time.time())
        expires = timeNow + expires_in - fiveMin
        data["expires"] = expires
        
        # update to new values while preserving other existing key/values
        existingToken.update(data)
        self.tokens[user_Id] = existingToken
        
        return access_token
    
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
        
        if user_Id in self.tokens:
            
            user_token = self.tokens.get(user_Id, {})
            expires = user_token.get('expires', 0)
            timeNow = int(time.time())
            
            if(expires > timeNow):
                logger.info('Bearer: Token is valid.')
                return user_token.get('access_token')
            
            else:
                logger.info('Bearer: Token expired.')
                return self.authorize(user_Id)
            
        else:
            logger.info('Bearer: Token not found.')
            return self.authorize(user_Id)


class Authenticator(AuthBase):
    """docstring for Authenticator"""
    def __init__(self, client_id, client_secret, scope, tokens = {}):
        super(Authenticator, self).__init__(scope=scope, tokens=tokens)
        
        prefs = {
            "access_type": "offline",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "response_type": "code"
        }
        
        self.prefs.update(prefs)
    
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
            data = self._exchange(code)
            
            return self.check_store_Token(user_Id, data)
    
    def _exchange(self, code):
        """docstring for _exchange"""
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
                return self.check_store_Token(user_Id, data)
            else:
                # removing token, prevents refreshing loops
                self.tokens.pop(user_Id, None)
                return self.authorize(user_Id)


class ServiceAuthenticator(AuthBase):
    """docstring for ServiceAuthenticator"""
    def __init__(self, client_email, private_key, scope, tokens = {}):
        super(ServiceAuthenticator, self).__init__(scope=scope, tokens=tokens)
        
        prefs = {
            'client_email': client_email,
            'private_key': private_key,
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        }
        
        self.prefs.update(prefs)
        
    def _signedPayload(self, user_Id = None):
        """docstring for _signedPayload"""
        logger.debug("prefs %s", json.dumps(self.prefs))
        now = long(time.time())
    
        payload = {
          'aud': self.prefs.get('token_uri'),
          'scope': self.prefs.get('scope'),
          'iat': now,
          'exp': now + 3600,
          'iss': self.prefs.get('client_email')
        }
        
        if user_Id:
            payload['sub'] = user_Id
        
        logger.debug(payload)
        
        private_key = self.prefs.get('private_key')
        
        assertion = crypt.make_signed_jwt(crypt.Signer.from_string(private_key), payload)
        
        return assertion
    
    def refresh(self, user_Id = None):
        """docstring for refresh"""
        
        data = {
            'assertion': self._signedPayload(user_Id),
            'grant_type': self.prefs.get('grant_type')
        }
        logger.debug(data)
        
        r = WebRequest()
        result = r.post(self.prefs.get('token_uri'), data=data)
        
        if result.ok:
            return result.json()
        else:
            print result.text
            raise BaseException("Something went wrong. Code %s", result.status_code)
    
    def authorize(self, user_Id = None):
        """ More info: https://developers.google.com/accounts/docs/OAuth2InstalledApp """
        
        if user_Id in self.tokens:
            logger.debug("Got token for user_Id: " + str(user_Id) + ", needs refreshment.")
        else:
            logger.debug("Requesting new token for user_Id: " + str(user_Id))
        
        data = self.refresh(user_Id)
        return self.check_store_Token(user_Id, data)


def main():
    """docstring for main"""
    pass

if __name__ == '__main__':
    main()