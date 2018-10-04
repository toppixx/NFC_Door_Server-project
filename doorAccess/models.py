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

    def dacRequestP1(self,uuid):
        for i in self.userKeys.all():
            if re.sub('-', '',str(i.keyUUID)) == re.sub('-', '',str(uuid)):
                self.accessingUUID = re.sub('-', '',str(uuid))
                self.TDAT =  TDAT.TDATchecker().init()
            self.save()
            return str(self.TDAT)
        return 'fail'

    def dacRequestP2(self, uuid, ecUDID):
        rowDoorList = 0
        for i in self.listOfDoors.all():
            rowDoorList = rowDoorList+1
            print("row %d:" %(rowDoorList))
            ecUDID = ecUDID.lower()
            #DEBUG
            # toHashStr = self.TDAT+re.sub('-', '',str(i.doorUDID))
            # print("\SERVER plain to hash: String(TDAT + UDID)")
            # print(toHashStr)
            # print("\nSERVER hexed to hash: String(TDAT + UDID)")
            # print("".join("{:02x}".format(ord(c)) for c in toHashStr))
            # encToHashStr = (self.TDAT+re.sub('-', '',str(i.doorUDID))).encode()
            #DEBUG

            toHashStr = (self.TDAT+re.sub('-', '',str(i.doorUDID)))

            sha256Hash = hashlib.sha256(toHashStr.encode('ASCII'))

            print("\nSERVER hexed to hash: String(TDAT + UDID)")
            print("input:\t" + toHashStr)
            print("output:\t" +str(sha256Hash.hexdigest()))
            print("\nREMOTE hexed to hash: SHA256(String(TDAT + UDID))")
            print(str(ecUDID))
            print("\ngoint to compare calculated and hashed SHA256 Hash")
            print("server-hashed: "+sha256Hash.hexdigest())
            print("remote-hasehd: "+ ecUDID)
            if str(ecUDID) == str(sha256Hash.hexdigest()):
                print("\n--------------------------------------------")

                print("\ncalculated SHA256 Hash and recieve Hash found a mach")
                print("\tfound UDID of the accesing Door is: \n\t"+i.doorUDID)
                print("\n--------------------------------------------")

                print("\n\nsetup Data for enshuring encrypted communication")
                iv = get_random_string(16)
                print("generated Salt (iv) for AES encryption is:\n\t"+iv)
                print("\nstoring Data of the Accesing UUID and UDID for next actions")
                self.accessingUUID = uuid
                self.encryptionSalt = iv
                self.accesingUDID = i.doorUDID
                self.encryptionKey = i.doorUDID
                self.save()

                print("\n--checking allowence of the accesing UUID--")
                #TODO i think this is already complited in views bevor calling dacRequestP2()
                print("searching for the key entry of the accessing UUID to get the right AES Encryption Key which one the NFC-Tag is encrypted")
                rowKeyList = 0
                for n in self.userKeys.all():
                    rowKeyList = rowKeyList +1;
                    print("\nkeyList row %d :" %(rowKeyList))
                    print("compatre:\n" + n.keyUUID + " (keyListElement UUID)")
                    print(self.accessingUUID + " (accesing UUID()\n")
                    if re.sub('-', '',str(n.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):

                        print("going to cypher the AES Encryption Key of the NFC-Tag")
                        iv = self.encryptionSalt
                        encryptionKey = self.encryptionKey
                        plainText = n.AESEncryptKey

                        aesCryptor = AesCryption.AES128CryptoLib()
                        cypherText = aesCryptor.encrypt(plainText, encryptionKey, iv)
                        #plainTxtDecrypt = aesCryptor.decrypt(cypherText,encryptionKey,iv)

                        print("iv:\t\t" + iv)
                        print("encryptionKey:\t" + encryptionKey)
                        print("plainTxt:\t" + plainText)
                        print("cypherText:\t" + str(cypherText))
                        #print("For testing:")
                        #print("decyptedText:\t" + str(plainTxtDecrypt))

                        return cypherText.hex() , bytes(iv,'ascii').hex()

        print("\ncomparing SHA256 Hashes failed!!!")
        return 'fail', 'fail'

    def dacRequestP3(self,uuid, keyHash, TDAT3):
        #TODO decrypt keyHash check Permission and return DoorHandle if true else -1
        #debugStyle
        print("uuid:\t%s" %(uuid))
        print("keyHash:\t%s" %(keyHash))
        print("TDAT3:\t %s" %(TDAT3))
        if(uuid==self.accessingUUID):
            rowKeyList = 0
            for n in self.userKeys.all():
                rowKeyList = rowKeyList +1;
                print("\nkeyList row %d :" %(rowKeyList))
                print("compatre:\n" + n.keyUUID + " (keyListElement UUID)")
                print(self.accessingUUID + " (accesing UUID()\n")
                if re.sub('-', '',str(n.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):
                    print("going to decrypt the cypher text with Setion AES Encryption Key of the Connection")
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
                    print("cipherText:\t" + str(cipherText))
                    print("plainText:\t" + str((plainTxtDecrypt)))
                    print("UTID:\t\t" + str(n.keyUTID ))
                    print("UTID bytes:\t"+ str(bytes(n.keyUTID,'ascii')))
                    #print("plainTxt:\t"+str(plainTxtDecrypt.decode('ASCII' )))
                    print(bytes(bytearray.fromhex(''.join(hexStr))))
                    for m in self.listOfDoors.all():
                        print(m)
                        print("m.doorUDID == self.accesingUDID")
                        print(m.doorUDID == self.accesingUDID)
                        print("m.doorUDID:\t" + str(m.doorUDID))
                        print("self.accesingUDID:\t" + str(self.accesingUDID))

                        print("n.keyUTID== plainTxtDecrypt")
                        print(n.keyUTID== plainTxtDecrypt)
                        print("n.keyUTID:\t" + str(n.keyUTID))
                        print("plainTxtDecrypt:\t" + str(plainTxtDecrypt.decode('ascii')))
                        print("str(bytes(n.keyUTID,'ascii'):\t" + n.keyUTID)

                        if m.doorUDID == self.accesingUDID and n.keyUTID== str(plainTxtDecrypt).decode('ascii')):
                            print(true)
                            return 'true'


                    #listOfDoors->Door->UDID
                    #if(str(n.keyUTID) == str(plainTxtDecrypt.decode('ASCII'))):
                    #    return 'true'

                else:
                    return 'uuid not found'
        else:
            return 'not the same uuid connection sequenz Error'

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
