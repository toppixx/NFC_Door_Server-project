from rest_framework import serializers

from . import models

class HelloSerializer(serializers.Serializer):
    """Serializes a name field for testting our APIView"""
    name =  serializers.CharField(max_length=10)


class UserProfileSerializer(serializers.ModelSerializer):
    """ A serializer for oure user profile objects"""

    class Meta:
        model = models.UserProfile
        fields = ('id', 'email', 'name', 'password')
        extra_kwargs = {'password' : {'write_only': True}}


    def create(self, validated_data):
        """Create and return a new user"""

        user = models.UserProfile(
            email = validated_data['email'],
            name = validated_data['name']
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

class CreateNewUserSerializer(serializers.ModelSerializer):
    """ A serializer accessable for staff users to create a new user profile objects"""

    class Meta:
        model = models.UserProfile
        fields = ('email', 'name', 'password')
        extra_kwargs = {'password' : {'write_only': True},  'email': {'write_only': True},'name' : {'write_only': True}}



    def create(self, validated_data):
        """Create and return a new user"""

        user = models.UserProfile(
            email = validated_data['email'],
            name = validated_data['name']
        )
        user.set_password(validated_data['password'])
        user.save()

        return user


class ProfileFeedItemSerializer(serializers.ModelSerializer):
    """A serializer for profile feed Items."""

    class Meta:
        model= models.ProfileFeedItem
        fields = ('id', 'user_profile', 'status_text', 'created_on', 'nfc_tag_list')
        extra_kwargs ={'user_profile':{'read_only':True}}


class DoorAccesControllSerializer(serializers.ModelSerializer):
    """A serializer for door access controll."""
    nfc_tag =  serializers.CharField(max_length=255)

    class Meta:
        model= models.DoorNfcTagModel
        fields = ('id', 'door_nfc_tag', 'door_name')
        #extra_kwargs ={'user_profile':{'read_only':True}}

    #def create(self, validated_data):
    #    print("valid_data['nfc_tag']=="+validated_data['nfc_tag'])
    #    return validated_data['nfc_tag']==False ## TODO: compare to all nfc_tag listed for the door user
