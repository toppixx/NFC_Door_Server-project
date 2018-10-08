import uuid
from django.utils.crypto import get_random_string
from os import  urandom
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager
from doorAccess import models as doorAccess_models
import json
import hashlib
import re
from doorAccess import AesCryption
import base64
import codecs
import binascii

from doorAccess import TDAT

from Crypto.Cipher import AES

class UserProfileManager(BaseUserManager):
    """Helps django to work with our custom user model."""

    def create_user(self, email, name, password):
        """ Creates a new user profile object."""

        if not email:
            raise ValueError('Useres must have an email address.')
        email = self.normalize_email(email)
        user = self.model(email=email, name=name)

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, password):
        """createse and saves a new superuser with given details."""

        user = self.create_user(email, name ,password)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user

class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Represents a "user profile" inside our system."""

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    nfc_tag_list = models.TextField()
    nfc_tag_list_group = models.TextField()
    objects = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def get_full_name(self):
        """Used to get a users full name."""
        return self.name

    def get_short_name(self):
        """Used to get a users short name."""
        return self.name[:10]

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.email




#this is old version need to be replaced with new functionality
class DoorNfcTagModel(models.Model):
    """A NFC tag of a spezifik door"""
    door_name = models.CharField(max_length=15)
    nfc_tag = models.CharField(max_length=255)



class ProfileFeedItem(models.Model):
    """Profile status update."""
    user_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)#, related_name='user_profile_ProfileFeedItem')
    status_text = models.CharField(max_length=255);
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return model as a String"""
        return self.status_text


class NfcDoor(models.Model):
    """Model of a Door"""
    nameOfDoor   = models.CharField(max_length=255, default="door with no Name")
    doorUDID     = models.CharField(max_length=16, default=get_random_string(16))#, editable=False)
    permissionStr= models.CharField(max_length=32, default=get_random_string(32))
    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoor



class NfcDoorGroup(models.Model):
    """Model of a Groups for multiple doors or groups"""
    nameOfDoorGroup     = models.CharField(max_length=255, default="group with no name")
    listOfDoors = models.ManyToManyField(NfcDoor, related_name = 'listOfDoors_NfcDoorGroup')

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoorGroup


class NfcKey(models.Model):

    """Model for a NfcKey"""
    id = models.AutoField(primary_key=True)
    keyName      = models.CharField(max_length=255, default="key with no name")
    keyUUID      = models.CharField(max_length=20, default=get_random_string(20) )#,editable=False)
    keyUTID      = models.CharField(max_length=32, default=get_random_string(32) )#,editable=False)
    AESEncryptKey= models.CharField(max_length=32, default=get_random_string(16))
    accesTrue    = models.CharField(max_length=32, default=get_random_string(32))
    internalUUID = models.UUIDField(default=uuid.uuid4 ,editable=False)
    @property
    def category_id(self):
        return self.id

    def getId(self):
        return self.id
    def __str__(self):

        """django useses this when it need to convert the object to a string"""
        return  str(self.keyUUID)
    def getInternalUUID(self):
        print(self.internalUUID)
        print(re.sub('-', '',str(self.internalUUID)))
        return str(re.sub('-', '',str(self.internalUUID)))

    def getSelf(self):
        return self



class NfcListOfUsers(models.Model):
    """Model of a List of all Users"""
    def randomString(value):
        return get_random_string(value)

    def getUserKeys(self):
        return self.userKeys

    def calcTDATSignature(self, sigStr, iv, encKey):
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


    def dacRequestP1(self,uuid):
        print("------------------------------------------------------------------------")
        print("looking for the right Key Entry in the KeyList")

        for i in self.userKeys.all():
            print("compatre:\n" + i.keyUUID + " (keyListElement UUID)\n"+uuid + " (accesing UUID()\n")
            if re.sub('-', '',str(i.keyUUID)) == re.sub('-', '',str(uuid)):
                self.accessingUUID = re.sub('-', '',str(uuid))
                self.TDAT =  TDAT.TDATchecker().init()

                print("------------------------------------------------------------------------")
                print("setup Data for enshuring encrypted communication")
                iv = get_random_string(16)
                print("generated Salt (iv) for AES-Encryption\n\niv:\t"+iv)
                self.encryptionSalt = iv
                print("------------------------------------------------------------------------")

                self.save()
                print("found")
                print("------------------------------------------------------------------------")

                return str(self.TDAT) , bytes(self.encryptionSalt,'ascii').hex()
        print("no match")
        print("------------------------------------------------------------------------")
        return 'fail'

    def dacRequestP2(self, uuid, ecUDID):
        print("Phase 2:\nRecieving a SHA256 Hash from remote calculated on TDAT+UDID, to get the Right UDID and encryption Key")
        print("going to calculate all SHA256(TDAT+UDID) Hashes of all Doors, comparing each with the recieved one")
        print("if a match is found the NFC-AES-KEY of the accessing NFC-Tag will be send encrypted to the UDID Terminal")
        print("\n------------------------------------------------------------------------\n")
        print("looking for the right Key Entry in the KeyList")
        if(True): #check old one
            #self.TDAT = calcTDASignature(self.TDAT); #calc next one
            for l in self.userKeys.all():
                if re.sub('-', '',str(l.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):
                    print("found")
                    print("------------------------------------------------------------------------")
                    print("------------------------------------------------------------------------")
                    print("looking for the accessing door")
                    print("for this make a row and check all calculated SHA256 against the incoming SHA256")
                    print("------------------------------------------------------------------------")
                    for i in self.listOfDoors.all():
                        ecUDID = ecUDID.lower()
                        print("------------------------------------------------------------------------")
                        print("\nRemote Sha256 Hash SHA256(String(TDAT + UDID)):")
                        print(str(ecUDID))
                        print("------------------------------------------------------------------------")

                        toHashStr = (self.TDAT+re.sub('-', '',str(i.doorUDID)))
                        print("------------------------------------------------------------------------")

                        print("calculating Server Sha256 Hash String(TDAT + UDID):\nTDAT:\t"+self.TDAT+"\nUDID:\t"+i.doorUDID+"\nTDAT+UDID:\t"+toHashStr)
                        sha256Hash = hashlib.sha256(toHashStr.encode('ASCII'))
                        print("SHA256 Hash (hex):\t" +str(sha256Hash.hexdigest()))
                        print("------------------------------------------------------------------------")

                        print("------------------------------------------------------------------------")
                        print("compare calculated and hashed SHA256 Hash\n")
                        print("server-hashed: "+sha256Hash.hexdigest())
                        print("remote-hasehd: "+ ecUDID)
                        print("------------------------------------------------------------------------")

                        if str(ecUDID) == str(sha256Hash.hexdigest()):
                            print("------------------------------------------------------------------------")
                            print("calculated SHA256 Hash and recieve Hash mached")
                            print("------------------------------------------------------------------------")
                            print("------------------------------------------------------------------------")
                            print("checking allowence of the accesing UUID")
                            print("------------------------------------------------------------------------")
                            for door in self.listOfDoors.all():
                                if door.doorUDID == self.accesingUDID:
                                    print("------------------------------------------------------------------------")
                                    print("searching for the key entry of the accessing UUID to get the right AES Encryption Key which one the NFC-Tag is encrypted\n")
                                    for n in self.userKeys.all():
                                        if re.sub('-', '',str(n.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):
                                            print("found UDID!! \nUDID of the accesing Door is:\t"+i.doorUDID)
                                            print("------------------------------------------------------------------------")
                                            print("------------------------------------------------------------------------")
                                            self.accessingUUID = uuid
                                            self.accesingUDID = i.doorUDID
                                            self.encryptionKey = i.doorUDID
                                            self.save()
                                            print("\nstoring Data of the Accesing UUID and UDID for next actions")
                                            print("------------------------------------------------------------------------")

                                            print("------------------------------------------------------------------------")
                                            print("cypher the NFC-AES-Key of the NFC-Tag\n")
                                            iv = self.encryptionSalt
                                            encryptionKey = self.encryptionKey
                                            plainText = n.AESEncryptKey

                                            aesCryptor = AesCryption.AES128CryptoLib()
                                            cypherText = aesCryptor.encrypt(plainText, encryptionKey, iv)

                                            print("iv:\t\t" + iv)
                                            print("encryptionKey:\t" + encryptionKey)
                                            print("plainTxt:\t" + plainText)
                                            print("cypherText:\t" + str(cypherText))
                                            print("------------------------------------------------------------------------")

                                            return cypherText.hex()
            else:
                print("TDAT error")
            print("------------------------------------------------------------------------")
            print("accesing UUID doesnt exist or has no rights to enter to door")
        print("\nPhase 2 failed!!!")
        return 'fail'

    def dacRequestP3(self,uuid, keyHash, TDAT3):
        #TODO short description
        print("------------------------------------------------------------------------")
        print("request with:")
        print("uuid:\t\t%s" %(uuid))
        print("keyHash:\t%s" %(keyHash))
        print("TDAT3:\t\t%s" %(TDAT3))
        print("------------------------------------------------------------------------")
        print("------------------------------------------------------------------------")
        print("looking for the right Key Entry in the KeyList\n")
        if(uuid==self.accessingUUID):
            rowKeyList = 0
            for key in self.userKeys.all():
                rowKeyList = rowKeyList +1;
                print("compare:\n" + key.keyUUID + " (keyListElement UUID)\n"+self.accessingUUID + " (accesing UUID()\n")
                if re.sub('-', '',str(key.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):
                    print("found")
                    print("------------------------------------------------------------------------")
                    print("------------------------------------------------------------------------")

                    print("going to decrypt the cypher text with Setion AES Encryption Key of the Connection\n")
                    iv = self.encryptionSalt
                    encryptionKey = self.encryptionKey

                    hexArr = ( keyHash.split(" ") )
                    hexStr = ""
                    for i in range(0,len(hexArr)):
                        hexArr[i] = hexArr[i].zfill(2)
                        hexStr = hexStr + hexArr[i] + ' '

                    cipherText = bytearray.fromhex(''.join(hexStr))
                    aesCryptor = AesCryption.AES128CryptoLib()
                    plainTxtDecrypt = aesCryptor.decrypt(bytes(cipherText),encryptionKey,iv)

                    print("iv:\t\t" + iv)
                    print("encryptionKey:\t" + encryptionKey)
                    print("cipherText:\t" + str(cipherText.hex().upper()))
                    print("plainText:\t" + str((plainTxtDecrypt.decode('ascii'))))
                    print("UTID:\t\t" + str(key.keyUTID ))
                    print("------------------------------------------------------------------------")

                    for door in self.listOfDoors.all():
                        if door.doorUDID == self.accesingUDID and key.keyUTID== plainTxtDecrypt.decode('ascii'):
                            print("------------------------------------------------------------------------")
                            print("create doorPermission=True SHA256(AES128(TDAT+permiisionStr))\n")
                            print("create AES128(TDAT+permissionStr)")
                            print("TDAT:\t\t" +self.TDAT)
                            print("permissionStr:\t" + door.permissionStr)
                            toHashStr = (self.TDAT+door.permissionStr)
                            print("toHashStr:\t" + toHashStr)

                            aesCryptor = AesCryption.AES128CryptoLib()
                            cipherText = aesCryptor.encrypt(str(toHashStr),encryptionKey,iv)
                            print("cipherText:\t" + cipherText.hex().upper())

                            print("\n\ncreate SHA256(AES128)")
                            sha256Hash = hashlib.sha256(cipherText.hex().upper().encode('ascii'))
                            print("SHA256 Hash (hex):\t" + str(sha256Hash.hexdigest().upper()))
                            print("------------------------------------------------------------------------")
                            return sha256Hash.hexdigest().upper()
                else:
                    print('uuid not found')
        else:
            print('connection sequenz Error')

        return 'fail'


    userName     = models.CharField(max_length=255)

    listOfDoorGroups = models.ManyToManyField(NfcDoorGroup, related_name='DoorGroup_NfcListOfUsers')
    listOfDoors  = models.ManyToManyField(NfcDoor, related_name = 'ListOfDoors_NfcListOfUsers')
    userKeys   = models.ManyToManyField(NfcKey,  related_name = 'ListOfKeys_NfcListOfUsers')

    TDAT         = models.CharField(max_length=32, default=randomString(16))#,editable=False)
    accessingUUID = models.CharField(max_length=20, default=randomString(20))
    accesingUDID = models.CharField(max_length=16, default=randomString(16))#,editable=False)
    encryptionKey= models.CharField(max_length=16, default=randomString(16))#, editable=False)    #do i need this one?
    encryptionSalt  = models.CharField(max_length=16, default=randomString(16))
    timeStamp    = models.DateTimeField(auto_now=True)

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.userName

#recieves UUID of NFC-TAg and sends TDAT
class NfcDACPhase1(models.Model):
    userKeys = models.CharField(max_length=20)

#recivese SHA256(Nfc-Tag-UUID + TDAT) and sends AES128(UDID)(AESEncryptionKey(NFC-TAG))
class NfcDACPhase2(models.Model):
    userKeys = models.CharField(max_length=20)
    keyHash = models.CharField(max_length=66)
    TDAT2 = models.CharField(max_length=32)

class NfcDACPhase3(models.Model):
    userKeys = models.CharField(max_length=20)
    #aesEncryptedNfcPw = models.CharField(max_length=16)
    keyHash = models.CharField(max_length=95)
    #aesSalt = models.CharField(max_length=16)
    TDAT3 = models.CharField(max_length=32)
