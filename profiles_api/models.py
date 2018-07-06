import uuid
from django.utils.crypto import get_random_string
from os import  urandom
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager
from profiles_api import models as profiles_api_models
import json
import hashlib
import re
from profiles_api import AesCryption




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
    nameOfDoor   = models.CharField(max_length=255)
    doorUUID     = models.UUIDField(primary_key=True, default=uuid.uuid4)#, editable=False)

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoor



class NfcDoorGroup(models.Model):
    """Model of a Groups for multiple doors or groups"""
    nameOfDoorGroup     = models.CharField(max_length=255)
    listOfDoors = models.ManyToManyField(NfcDoor, related_name = 'listOfDoors_NfcDoorGroup')

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoorGroup


class NfcKey(models.Model):
    def unique_rand_AES():
        return urandom(10)

    """Model for a NfcKey"""
    keyName     = models.CharField(max_length=255)
    keyUUID      = models.UUIDField(primary_key=True, default=uuid.uuid4 )#,editable=False)
    AESEncryptKey= models.TextField(max_length=32, default=get_random_string(32))

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return str(self.keyName + "\t\t\t   " + str(self.keyUUID))



class NfcListOfUsers(models.Model):
    """Model of a List of all Users"""
    def randomString(value):
        return get_random_string(value)


    def dacRequestP1(self,uuid):
        self.accessingUUID = uuid;
        self.TDAT =  get_random_string(256)
        #self.timeStamp = os.timeStamp()
        self.save()
        return str(self.TDAT)

    def dacRequestP2(self, ecUDID):
        print('\n ecUDID')
        print(ecUDID)
        for i in self.listOfDoors.all():
            sha256Hash = hashlib.sha256((self.TDAT+str(i.doorUUID)).encode())
            print(str(sha256Hash.hexdigest()))
            if str(ecUDID) == str(sha256Hash.hexdigest()):
                self.accesingUDID = i.doorUUID
                print('now it comes')
                self.encryptionKey = re.sub('-', '',str(i.doorUUID)) #self.accesingUDID
                print(self.encryptionKey)
                print(str(i.doorUUID))
                self.encryptionSalt = urandom(12)
                self.save()


                print('i was bevor the loop')
                for n in self.userKeys.all():
                    print('looping')
                    print(n.keyUUID)
                    print(self.accessingUUID)
                    if n.keyUUID == self.accessingUUID:
                        aesEncryption = AesCryption.AESCipher((str(self.encryptionKey)).encode('utf-8'))
                        print('hey')
                        test1, test = aesEncryption.encrypt(n.AESEncryptKey)
                        print('cypher')
                        print(test1)
                        print('salt')
                        print(test)
                        return test1, test
                        return aesEncryption.encrypt(n.AESEncryptKey)

        return 'fail', 'fail'


    userName     = models.CharField(max_length=255)

    listOfDoorGroups = models.ManyToManyField(NfcDoorGroup, related_name='DoorGroup_NfcListOfUsers')
    listOfDoors  = models.ManyToManyField(NfcDoor, related_name = 'ListOfDoors_NfcListOfUsers')
    userKeys   = models.ManyToManyField(NfcKey,  related_name = 'ListOfKeys_NfcListOfUsers')

    TDAT         = models.TextField(max_length=256, default=randomString(256))#,editable=False)
    accessingUUID = models.UUIDField(default = uuid.uuid4)
    accesingUDID = models.UUIDField(default = uuid.uuid4)#,editable=False)
    encryptionKey= models.TextField(max_length=32, default=randomString(32))#, editable=False)    #do i need this one?
    encryptionSalt  = models.TextField(max_length=32, default=randomString(32))
    timeStamp    = models.DateTimeField(auto_now=True)

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        #print(str(self))
        #return json.loads(str(self))
        return self.userName

#recieves UUID of NFC-TAg and sends TDAT
class NfcDACPhase1(models.Model):
    userKeys = models.TextField(max_length=32)

#recivese SHA256(Nfc-Tag-UUID + TDAT) and sends AES128(UDID)(AESEncryptionKey(NFC-TAG))
class NfcDACPhase2(models.Model):
    userKeys = models.TextField(max_length=32)
    keyHash = models.TextField(max_length=256)
    TDAT2 = models.TextField(max_length=256)

class NfcDACPhase3(models.Model):
    userKeys = models.TextField(max_length=32)
    aesEncryptedNfcPw = models.BinaryField(max_length=256)
    aesSalt = models.BinaryField(max_length=96)
    TDAT3 = models.TextField(max_length=256)
