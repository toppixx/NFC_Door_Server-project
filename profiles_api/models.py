import uuid
from django.utils.crypto import get_random_string
from os import  urandom
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager


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
    REQUIRED_FIELDS = ['name'] #?password, email?

    def get_full_name(self):
        """Used to get a users full name."""
        return self.name

    def get_short_name(self):
        """Used to get a users short name."""
        return self.name[:10]

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.email




class ProfileFeedItem(models.Model):
    """Profile status update."""
    user_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)#, related_name='user_profile_ProfileFeedItem')
    status_text = models.CharField(max_length=255);
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return model as a String"""
        return self.status_text



class DoorNfcTagModel(models.Model):
    """A NFC tag of a spezifik door"""
    door_name = models.CharField(max_length=15)
    nfc_tag = models.CharField(max_length=255)

#DOOR_NFC_LIST = models.DoorNfcTagModel.objects.all()

#class DoorNfcListModel(AbstractBaseUser):
class DoorNfcListModel(models.Model):
    """ a List of all NFC tag door elements"""
    door_nfc_list = models.ForeignKey('DoorNfcTagModel', on_delete=models.CASCADE)#, related_name= 'door_nfc_list_DoorNfcListModel')
    #door_nfc_list = models.OneToManyField(models.DoorNfcTagModel.objects.all())
    #door_nfc_list = models.CharField(max_length = 255, choices=DOOR_NFC_LIST, default = 1111)

class DoorNfcGroupModel(models.Model):
    group_name = models.CharField(max_length=30)
    door_nfc_tag_list = models.TextField()



class NfcDoor(models.Model):
    """Model of a Door"""
    nameOfDoor   = models.CharField(max_length=255)
    doorUUID     = models.UUIDField(primary_key=True, default=uuid.uuid4(), editable=False)
    #doorGroup    = models.ForeignKey(NfcListOfDoors, on_delete=models.CASCADE)
    #doorGroup    = models.ForeignKey(NfcDoorGroup, on_delete=models.CASCADE)#, related_name='doorGroup_NfcDoor')
    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoor



class NfcDoorGroup(models.Model):
    """Model of a Groups for multiple doors or groups"""
    nameOfDoorGroup     = models.CharField(max_length=255)
    ##listOfADoorGroup    = models.ManyToManyField(listOfADoorGroup, through='Visit')
    #
    listOfDoors = models.ManyToManyField(NfcDoor, related_name = 'listOfDoors_NfcDoorGroup')
    #listOfGroups = models.ManyToManyField(NfcDoorGroup, related_name = 'listOfDoorGroups_NfcDoorGroup', null=True)
    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoorGroup

class NfcMasterListOfAllDoorGroups(models.Model):
    """Model of the Master List of all Groups"""
    nameOfMasterDoorGroup = models.CharField(max_length=255);
    ##listOfDoorGroups = models.ManyToManyField(NfcDoorGroup, through='Visit')
    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfMasterDoorGroup

class NfcListOfDoors(models.Model):
    """Model of a List of all Doors"""
    nameOfDoorList = models.CharField(max_length=255)
    #listOfDoors  =  models.ManyToManyField(NfcDoor, through='Visit')
    #listOfDoors = models.ManyToManyField(NfcDoor,  through='NfcListOfUsers',related_name = 'listOfDoors_NfcListOfDoors')
    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.nameOfDoorList




class NfcMasterListOfKeys(models.Model):
    nameOfMasterKeyList = models.CharField(max_length=255);
    """Model of a List of Keys"""
    #list         = models.ManyToManyField(NfcKey, through='NfcVisitListOfKeys')

    # def __init__(self, *args, **kwargs):
    #     self.nameOfMasterKeyList = "KeyMasterList2"
    #     super(NfcMasterListOfKeys, self).__init__(self, *args, **kwargs)

    def __str__(self):
        self.save()
        """django useses this when it need to convert the object to a string"""
        return self.nameOfMasterKeyList
#
# class NfcListOfKeys(models.Model):
#     nameOfKeyList = models.CharField(max_length=255);
#     """Model of a List of Keys"""
#     #masterListOfKeys  = models.ForeignKey(NfcMasterListOfKeys, on_delete=models.CASCADE, related_name = 'MasterListOfKeys_NfcListOfKeys')
#     #list         = models.ManyToManyField(NfcKey, through='NfcVisitListOfKeys')
#     def __str__(self):
#         """django useses this when it need to convert the object to a string"""
#         return self.nameOfKeyList

class NfcKey(models.Model):
    """Model for a NfcKey"""
    keyUUID      = models.UUIDField(primary_key=True, default=uuid.uuid4(), editable=False)
    AESEncryptKey= models.BinaryField(max_length=128, default=urandom(128))
    #listOfKeys   = models.ForeignKey(NfcListOfKeys, on_delete=models.CASCADE)#, related_name='ListOfKeys_NfcKey')
    masterListOfKeys = models.ForeignKey(NfcMasterListOfKeys, on_delete=models.CASCADE)#, related_name = 'MasterListOfKeys_NfcKey')
    def create(self):
        """django useses this when it need to create a new NfcKey object"""
        return self

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return str(self.keyUUID)

# class UserProfileManager(BaseUserManager):
#     """Helps django to work with our custom user model."""
#
#     def create_user(self, email, name, password):
#         """ Creates a new user profile object."""
#
#         if not email:
#             raise ValueError('Useres must have an email address.')
#         email = self.normalize_email(email)
#         user = self.model(email=email, name=name)
#
#         user.set_password(password)
#         user.save(using=self._db)
#
#         return user
#
#     def create_superuser(self, email, name, password):
#         """createse and saves a new superuser with given details."""
#
#         user = self.create_user(email, name ,password)
#         user.is_superuser = True
#         user.is_staff = True
#         user.save(using=self._db)
#
#         return user
#
class NfcListOfUsers(models.Model):
    """Model of a List of all Users"""
    userName     = models.CharField(max_length=255)

    listOfDoorGroups = models.ManyToManyField(NfcDoorGroup, related_name='DoorGroup_NfcListOfUsers')
    listOfDoors  = models.ManyToManyField(NfcDoor, related_name = 'ListOfDoors_NfcListOfUsers')
    #listOfKeys   = models.ForeignKey(NfcListOfKeys, on_delete=models.CASCADE, related_name = 'ListOfKeys_NfcListOfUsers')
    #nfcKey = NfcKey().save()

    TDAT         = models.TextField(max_length=256, default=get_random_string(length=256),editable=False)
    accesingUDID = models.TextField(max_length=256, default=get_random_string(length=256),editable=False)
    encryptionKey= models.TextField(max_length=256, default=get_random_string(length=256),editable=False)
    timeStamp    = models.DateTimeField(auto_now=True)

    # def __init__(self, *args, **kwargs):
    #     self.TDAT = get_random_string(length=256)
    #     self.accesingUDID = get_random_string(length=256)
    #     self.encryptionKey = get_random_string(length=256)
    #     #self.save()
    #     super(NfcListOfUsers, self).__init__(self, *args, **kwargs)

    def __str__(self):
        """django useses this when it need to convert the object to a string"""
        return self.userName
