import hashlib
from django.utils.crypto import get_random_string
from doorAccess import AesCryption

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
    def calcSignature(sigStr, iv, encKey):
        print("------------------------------------------------------------------------")
        print("calculate next TDAT signature")
        print("incoming signature String:\n" + sigStr)
        print("calculate AES128(signature String)")
        aesCryptor = AesCryption.AES128CryptoLib()
        cipherText = aesCryptor.encrypt(str(sigStr),encKey,iv)
        print("cipherText:\n" + cipherText.hex().upper())
        print("\ncalculate SHA256(AES128)")
        sha256Hash = hashlib.sha256(cipherText.hex().upper().encode('ascii'))
        print("signature:\t"+sha256Hash.hexdigest().upper())
        print("return:\t")
        print(sha256Hash.hexdigest().upper())

        print("------------------------------------------------------------------------")
        return sha256Hash.hexdigest().upper()



    def check(incomingTDAT, oldTDAT, iv, encKey):
        print("------------------------------------------------------------------------")
        print("checking incommingTDAT against calculated next TDAT depending on oldTDAT")
        print("returning True or False depending on match\n")

        newTDAT = TDATchecker.calcSignature(oldTDAT, iv, encKey)
        print("incomingTDAT:\t"+incomingTDAT)
        print("new TDAT:\t"+newTDAT+"\n")

        if(incomingTDAT==newTDAT):
            print("matched")
            print("------------------------------------------------------------------------")
            return True
        else:
            print("failed")
            print("------------------------------------------------------------------------")
            return False

    def init(self):
         return get_random_string(64)
