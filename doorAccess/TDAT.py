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
    def update(self, oldTDAT, , passphrase, IV):
        toHashStr = tdat+passphrase+IV
        return hashlib.sha256(toHashStr.encode('ASCII'))


    def check(self,incTDAT, oldTDAT, passphrase, iv):
        toHashStr = tdat+passphrase+IV
        tdat = hashlib.sha256(toHashStr.encode('ASCII'))
        if(tdat==self.TDAT):
            return True
        else:
            return False

    def init(self):
         return get_random_string(32)
