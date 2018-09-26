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
    doorUUID     = models.CharField(max_length=16, default=get_random_string(16))#, editable=False)

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
                self.TDAT =  get_random_string(32)
        #self.timeStamp = os.timeStamp()
            self.save()
            return str(self.TDAT)
        return 'fail'

    def dacRequestP2(self, ecUDID):
        for i in self.listOfDoors.all():
            ecUDID = ecUDID.lower()
            print("hiere")
            toHashStr = self.TDAT+re.sub('-', '',str(i.doorUUID))
            print("plain toHashStr")
            print(toHashStr)
            print("hexed")
            #print(toHashStr.hexdigest())
            print("".join("{:02x}".format(ord(c)) for c in toHashStr))
            print(toHashStr)
            print("\n\r")
            encToHashStr = (self.TDAT+re.sub('-', '',str(i.doorUUID))).encode()

            print("encoded toHashStr")
            print(encToHashStr)
            print("hexed")
            #print(codecs.decode(encToHashStr, "bin"))

            print("\n\r")
            sha256Hash = hashlib.sha256((self.TDAT+re.sub('-', '',str(i.doorUUID))).encode('ASCII'))
            print("\n\r")
            print("sha256.hexdigest()")
            print(str(sha256Hash.hexdigest()))
            print("\n\r")
            print("ecUDID")
            print(str(ecUDID))
            print("end")
            if str(ecUDID) == str(sha256Hash.hexdigest()):
                print("Strings mached")
                print(i.doorUUID)
                self.accesingUDID = i.doorUUID
                self.encryptionKey = i.doorUUID #self.accesingUDID
                self.encryptionSalt = get_random_string(16)
                print(self.encryptionSalt)
                self.save()
                for n in self.userKeys.all():
                    print(n.keyUUID)
                    print(self.accessingUUID)
                    if re.sub('-', '',str(n.keyUUID)) == re.sub('-', '',str(self.accessingUUID)):
                        #aesEncryption = AesCryption.AESCipher((str(self.encryptionKey)).encode('utf-8'))
                        #return aesEncryption.encrypt(n.AESEncryptKey)
                        # print("\n\raesEncryptKeyOfNFCTag")
                        # print(n.AESEncryptKey)
                        # print("\n\rsalt")
                        # print(self.encryptionSalt)
                        # print("\n\rencryption Key")
                        # print(self.encryptionKey)
                        # self.encryptionSalt = "f3Dnj6J0F3y9cVJI"
                        # print("\n\rhex ecryption Salt")
                        # print(bytes(self.encryptionSalt,'ascii'))
                        # print("\n\rhex AESEncrypted Key plain text")
                        #
                        # print(bytes(self.encryptionSalt,'ascii').hex())
                        # print(bytes(n.AESEncryptKey, 'ascii'))
                        # print(bytes(n.AESEncryptKey, 'ascii').hex())
                        # print("\n\rhex encryption key")
                        #
                        # print(bytes(self.encryptionKey, 'ascii'))
                        # print(bytes(self.encryptionKey, 'ascii').hex())
                        # cypher = str(AesCryption.encrypt(bytes(n.AESEncryptKey, 'ascii'), bytes(self.encryptionKey, 'ascii'), bytes(self.encryptionSalt,'ascii')).hex())
                        # #salt = self.encryptionSalt
                        #
                        # ''.join(hex(ord(x))[2:] for x in self.encryptionSalt)
                        # #salt = binascii.hexlify(self.encryptionSalt);
                        # key = bytes(self.encryptionKey, 'ascii')
                        # salt = self.encryptionSalt
                        # cipher = AES.new(key, AES.MODE_CBC, salt)
                        # msg = cipher.encrypt(b'Attack at dawn12')
                        # # cipher.nonce = bytes(self.encryptionSalt,'ascii')
                        # print("msg")
                        # print(msg.hex())
                        # print("salt")
                        # print(salt)
                        # print()
                        # print("cypher")
                        # print(cypher)
                        # print("salt")
                        # print(salt)
                        #return msg , salt

                        #iv = "TestTestTestTest"
                        iv = self.encryptionSalt
                        print("iv")
                        print(iv)
                        #ecKey = "cKeycKeycKeycKey"
                        ecKey = self.encryptionKey
                        print("ecKey")
                        print(ecKey)
                        #plainTxt = "0123456789abcdef"
                        plainTxt = n.AESEncryptKey
                        print("plainTxt")
                        print(plainTxt)
                        aesTest = AesCryption.AES128test()

                        print("\n\rplainTxt")
                        print(plainTxt)
                        ecTxt = aesTest.encrypt(plainTxt, ecKey, iv)

                        Txt = aesTest.decrypt(ecTxt,ecKey,iv)
                        print("decypted Text")
                        print(str(Txt))
                        return ecTxt.hex() , bytes(iv,'ascii').hex()

        return 'fail', 'fail'

    def dacRequestP3(self, uuid, aesEncryptedNfcPw,aesSalt):
        #debugStyle
        aesSalt = aesSalt.encode('utf-8')
        aesEncryptedNfcPw = aesEncryptedNfcPw.encode('utf-8')
        #debugStyle End
        self.encryptionSalt = aesSalt
        #aesDecrypt = AesCryption.AESCipher((str(self.encryptionKey)).encode('utf-8'))
        #nfcUTID = aesDecrypt.decrypt(aesEncryptedNfcPw, aesSalt)
        print(self)
        print(uuid)
        for i in self.userKeys.all():
            print(i.keyUUID)
            if re.sub('-', '',str(i.keyUUID)) == uuid:
                print(re.sub('-', '',str(i.keyUUID)))
                nfcUTID = AesCryption.decrypt(aesEncryptedNfcPw, self.encryptionKey, self.encryptionSalt)
                if i.keyUTID == nfcUTID:
                    return 'UTID was true'
                    return hashlib.sha256(sef.accesingUDID+self.NfcKey.accesTrue).hexdigest()
                else:
                    return 'UTID was false'
            else:
                return 'uuid not found'
        return 'fail'

    userName     = models.CharField(max_length=255)

    listOfDoorGroups = models.ManyToManyField(NfcDoorGroup, related_name='DoorGroup_NfcListOfUsers')
    listOfDoors  = models.ManyToManyField(NfcDoor, related_name = 'ListOfDoors_NfcListOfUsers')
    userKeys   = models.ManyToManyField(NfcKey,  related_name = 'ListOfKeys_NfcListOfUsers')

    TDAT         = models.CharField(max_length=32, default=randomString(16))#,editable=False)
    accessingUUID = models.CharField(max_length=7, default=randomString(7))
    accesingUDID = models.CharField(max_length=16, default=randomString(16))#,editable=False)
    encryptionKey= models.CharField(max_length=16, default=randomString(16))#, editable=False)    #do i need this one?
    encryptionSalt  = models.CharField(max_length=16, default=randomString(16))
    timeStamp    = models.DateTimeField(auto_now=True)

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        #print(str(self))
        #return json.loads(str(self))
        return self.userName

#recieves UUID of NFC-TAg and sends TDAT
class NfcDACPhase1(models.Model):
    userKeys = models.CharField(max_length=7)

#recivese SHA256(Nfc-Tag-UUID + TDAT) and sends AES128(UDID)(AESEncryptionKey(NFC-TAG))
class NfcDACPhase2(models.Model):
    userKeys = models.CharField(max_length=7)
    keyHash = models.CharField(max_length=66)
    TDAT2 = models.CharField(max_length=32)

class NfcDACPhase3(models.Model):
    userKeys = models.CharField(max_length=7)
    aesEncryptedNfcPw = models.CharField(max_length=16)
    aesSalt = models.CharField(max_length=16)
    TDAT3 = models.CharField(max_length=32)
