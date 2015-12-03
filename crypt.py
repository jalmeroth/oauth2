#!/usr/bin/env python
"""
This code is borrowed from Googles oauth2client-library: https://code.google.com/p/google-api-python-client/downloads/list
"""
import json
import base64
import logging


logger = logging.getLogger(__name__)


try:
  from OpenSSL import crypto


  class OpenSSLSigner(object):
    """Signs messages with a private key."""

    def __init__(self, pkey):
      """Constructor.

      Args:
        pkey, OpenSSL.crypto.PKey (or equiv), The private key to sign with.
      """
      self._key = pkey

    def sign(self, message):
      """Signs a message.

      Args:
        message: string, Message to be signed.

      Returns:
        string, The signature of the message for the given key.
      """
      return crypto.sign(self._key, message, 'sha256')

    @staticmethod
    def from_string(key, password='notasecret'):
      """Construct a Signer instance from a string.

      Args:
        key: string, private key in PKCS12 or PEM format.
        password: string, password for the private key file.

      Returns:
        Signer instance.

      Raises:
        OpenSSL.crypto.Error if the key can't be parsed.
      """
      if key.startswith('-----BEGIN '):
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
      else:
        pkey = crypto.load_pkcs12(key, password).get_privatekey()
      return OpenSSLSigner(pkey)

except ImportError:
  OpenSSLSigner = None


  class PyCryptoSigner(object):
    """Signs messages with a private key."""

    def __init__(self, pkey):
      """Constructor.

      Args:
        pkey, OpenSSL.crypto.PKey (or equiv), The private key to sign with.
      """
      self._key = pkey

    def sign(self, message):
      """Signs a message.

      Args:
        message: string, Message to be signed.

      Returns:
        string, The signature of the message for the given key.
      """
      return PKCS1_v1_5.new(self._key).sign(SHA256.new(message))

    @staticmethod
    def from_string(key, password='notasecret'):
      """Construct a Signer instance from a string.

      Args:
        key: string, private key in PEM format.
        password: string, password for private key file. Unused for PEM files.

      Returns:
        Signer instance.

      Raises:
        NotImplementedError if they key isn't in PEM format.
      """
      if key.startswith('-----BEGIN '):
        pkey = RSA.importKey(key)
      else:
        raise NotImplementedError(
            'PKCS12 format is not supported by the PyCrpto library. '
            'Try converting to a "PEM" '
            '(openssl pkcs12 -in xxxxx.p12 -nodes -nocerts > privatekey.pem) '
            'or using PyOpenSSL if native code is an option.')
      return PyCryptoSigner(pkey)

except ImportError:
  PyCryptoSigner = None


if OpenSSLSigner:
  Signer = OpenSSLSigner
elif PyCryptoSigner:
  Signer = PyCryptoSigner
else:
  raise ImportError('No encryption library found. Please install either '
                    'PyOpenSSL, or PyCrypto 2.6 or later')


def _urlsafe_b64encode(raw_bytes):
  return base64.urlsafe_b64encode(raw_bytes).rstrip('=')


def _urlsafe_b64decode(b64string):
  # Guard against unicode strings, which base64 can't handle.
  b64string = b64string.encode('ascii')
  padded = b64string + '=' * (4 - len(b64string) % 4)
  return base64.urlsafe_b64decode(padded)


def _json_encode(data):
  return json.dumps(data, separators = (',', ':'))


def make_signed_jwt(signer, payload):
  """Make a signed JWT.

  See http://self-issued.info/docs/draft-jones-json-web-token.html.

  Args:
    signer: crypt.Signer, Cryptographic signer.
    payload: dict, Dictionary of data to convert to JSON and then sign.

  Returns:
    string, The JWT for the payload.
  """
  header = {'typ': 'JWT', 'alg': 'RS256'}

  segments = [
          _urlsafe_b64encode(_json_encode(header)),
          _urlsafe_b64encode(_json_encode(payload)),
  ]
  signing_input = '.'.join(segments)

  signature = signer.sign(signing_input)
  segments.append(_urlsafe_b64encode(signature))

  logger.debug(str(segments))

  return '.'.join(segments)