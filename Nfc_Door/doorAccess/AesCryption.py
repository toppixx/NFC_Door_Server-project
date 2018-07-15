# #from https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
#
# import base64
# import hashlib
# from Crypto import Random
# from Crypto.Cipher import AES
#
# class AESCipher(object):
#
#     def __init__(self, key):
#         self.key = key
#
#     def encrypt(self, raw):
#         raw = self._pad(raw)
#         iv = Random.new().read(AES.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return (base64.b64encode(iv + cipher.encrypt(raw)), iv)
#
#     def decrypt(self, enc, iv):
#         #enc = base64.b64decode(enc)
#         #iv = base64.b64decode(iv)
#         #iv = enc[:AES.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
#
#     def _pad(self, s):
#         return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
#
#     @staticmethod
#     def _unpad(s):
#         return s[:-ord(s[len(s)-1:])]
#

from Crypto import Random
from Crypto.Cipher import AES
import base64

BLOCK_SIZE=32

def encrypt(message, passphrase, IV):
    """ function to encrypt with AES. (message, passphase, IV)"""
    # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
    #IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    #return base64.b64encode(aes.encrypt(message))
    return (aes.encrypt(message))

def decrypt(encrypted, passphrase, IV):
    """ function to decrypt with AES. (encrypted, passphase, IV)"""
    #IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    #return aes.decrypt(base64.b64decode(encrypted))
    return aes.decrypt((encrypted))