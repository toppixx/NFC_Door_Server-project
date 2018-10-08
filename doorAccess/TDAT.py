import hashlib
from django.utils.crypto import get_random_string

# Phase 1:
#   TDAT->init()->get_random_string(32)
#
#
# Phase 2:
#   TDAT->check(tdat,passphrase,iv)->boolen
#       true
#           TDAT->update(tdat,passphrase,iv)
#       false
#           TDAT->init()
#
#
# Phase 3:
#   TDAT->check(tdat,passphrase,iv)->boolen
#       true
#           TDAT->init()
#       false
#           TDAT->init()
#
#
#TDAT->check(newTdat, oldTdat,passphrase,iv)
#SHA256(oldTdat+passphrase+iv)=newTdat
#
#
#TDAT->update(tdat,passphrase,iv)->SHA256(oldTdat+passphrase+iv)
#
#
#
class TDATchecker():
    def nextTDATSignature(self, sigStr, iv, encKey):
        print("------------------------------------------------------------------------")
        print("calculate next TDAT signature\n")
        print("signature String:\t" + sigStr)
        print("\n\ncalculate AES128(signature String)\n")
        aesCryptor = AesCryption.AES128CryptoLib()
        cipherText = aesCryptor.encrypt(str(sigStr),encKey,iv)
        print("cipherText:\t" + cipherText.hex().upper())
        print("\n\ncalculate SHA256(AES128)\n")
        sha256Hash = hashlib.sha256(cipherText.hex().upper().encode('ascii'))
        print("SHA256(AES128(signature String))")
        print("signature:\t"+sha256Hash)
        print("------------------------------------------------------------------------")
        return sha256Hash

        #toHashStr = oldTDAT+passphrase+iv
        #return hashlib.sha256(toHashStr.encode('ASCII'))


    def check(self, incomingTDAT, oldTDAT, iv, encKey):
        print("------------------------------------------------------------------------")
        print("calculate next TDAT signature\n")
        print("signature String:\t" + oldTDAT)
        print("\n\ncalculate AES128(signature String)\n")
        aesCryptor = AesCryption.AES128CryptoLib()
        cipherText = aesCryptor.encrypt(str(oldTDAT),encKey,iv)
        print("cipherText:\t" + cipherText.hex().upper())
        print("\n\ncalculate SHA256(AES128)\n")
        sha256Hash = hashlib.sha256(cipherText.hex().upper().encode('ascii'))
        print("SHA256(AES128(signature String))")
        print("signature:\t"+sha256Hash)
        print("------------------------------------------------------------------------")
        if(incomingTDAT==sha256Hash):
            return True
        else:
            return False

    def init(self):
         return get_random_string(32)
