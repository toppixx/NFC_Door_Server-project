from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.permissions import IsAuthenticated

from . import serializers
from . import models
from . import permissions


import json
# Create your views here.

class HelloApiView(APIView):
        """ Test API View."""

        serializer_class = serializers.HelloSerializer

        def get(self, request, format=None):
            """returns a list of APIView features."""

            an_apiview = [
            'Uses HTTP methods as functions (get, post, patch, put, delete)',
            'It is simmilar to a traditional Django view',
            'Gives you the most controll over your logic',
            'Is mapped manualy to URLs',
            ]
            return Response({'message': 'Hello!', 'an_apiview': an_apiview})


        def post(self, request):
            """Create a hello message with our name."""
            serializer = serializers.HelloSerializer(data=request.data)

            if serializer.is_valid():
                name=serializer.data.get('name')
                message = 'Hello {0}'.format(name)
                return Response({'message':message})
            else:
                return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        def put(self,request, pk=None):
            """Handles updating an project"""

            return Response({'method':'put'})


        def patch(self,request, pk=None):
            """Patch request, only updates fields provided in the request"""

            return Response({'method':'put'})

        def delete(self,request, pk=None):
            """Patch request, only updates fields provided in the request"""

            return Response({'method':'delete'})

class HelloViewSet(viewsets.ViewSet):
    """Test API ViewSet"""

    serializer_class = serializers.HelloSerializer
    authentication_classes = (TokenAuthentication, )
    permission_classes = (permissions.UpdateOwnProfile, IsAuthenticated )

    def list(self, request):
        """ Return a Hello Message. """
        a_viewset = [
        'ueses actions (list, create, retrieve, update, partial_update,destroy)',
        'Automaticaly mapps to URLs using Routers',
        'Provides more functionality with less code.',
        ]

        return Response({'message':'Hello', 'a_viewset': a_viewset})

    def create(self, request):
        """Create a new Hello Message"""
        serializer = serializers.HelloSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.data.get('name')
            message = 'Hello {0}'.format(name)
            return Response({'message':message})

        else:
            return Response(serializer.errors,
            status = status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        """Handels getting an object by its ID"""
        return Response({'http_method': 'GET' })

    def update(self, request, pk=None):
        """Handels updating an Object  """
        return Response({'http_method':'PUT' })

    def partial_update(self, request, pk=None):
        """Handels updating part of an Object """
        return Response({'http_method':'PATCH' })

    def destroy(self, request, pk=None):
        """ Handels removing an Object"""
        return Response({'http_method':'DELETE' })



class UserProfileViewSet(viewsets.ModelViewSet):
    """ Handels creating,  reading and updating profiles"""

    serializer_class = serializers.UserProfileSerializer
    queryset = models.UserProfile.objects.all()
    authentication_classes = (TokenAuthentication, )
    permission_classes = (permissions.UpdateOwnProfile, IsAuthenticated )

    filter_backends = (filters.SearchFilter, )
    search_fields=('name', 'email',)


class LoginViewSet(viewsets.ViewSet):
    """Checks email and password and returns an auth token."""

    serializer_class = AuthTokenSerializer

    def create(self,request):
        """Use the ObtainAuthToken APIView to validate and create a token"""

        return ObtainAuthToken().post(request)

    def retrieve(self, request, pk=None):
        """Handels getting an object by its ID"""
        print(request)
        return Response({'http_method': 'POST' })


class UserProfileFeedViewSet(viewsets.ModelViewSet):
    """Handels creating, reading and updating profile feed Items."""

    serializer_class = serializers.ProfileFeedItemSerializer
    queryset = models.ProfileFeedItem.objects.all()
    authentication_classes = (TokenAuthentication, )
    permission_classes = (permissions.PostOwnStatus, IsAuthenticated, )


    def perform_create(self, serializer):
        """sets the user profile to the logged in user."""

        serializer.save(user_profile=self.request.user)


class DoorAccesControllViewSet(viewsets.ModelViewSet):
    """Test API ViewSet"""

    serializer_class = serializers.DoorAccesControllSerializer
    authentication_classes = (TokenAuthentication, )
    permission_classes = (permissions.DoorAccesControll, IsAuthenticated )
    queryset = models.DoorAccesControll.objects.all()

    def list(self, request):
        """ Return a True or False if nfc_tag is authenticated for that door. """
        a_viewset = [
        'ueses actions (create)',
        'Automaticaly mapps to URLs using Routers',
        'Provides more functionality with less code.',
        ]

        return Response({'a_viewset': a_viewset})

    def create(self, request):
        """Creates a door access query"""
        #serializer = serializers.DoorAccesControllSerializer(data=request.data)
        #print(request)
        serializer = serializers.DoorAccesControllSerializer(data=request.data)

        if serializer.is_valid():
            #print('serializer valid!')
            #print(serializer)
            nfc_tag = serializer.data.get('nfc_tag')
            access_flag = False
            #print(nfc_tag)
            #print("0")
            #print(request.user)
            #print(request.user.nfc_tag_list)
            nfc_tag_list = request.user.nfc_tag_list
            #print("1")
            #print(nfc_tag_list)
            #print("2")
            nfc_tag_list = json.loads(nfc_tag_list)
            #print(nfc_tag_list)
            #### TODO: get reali json tag_id and compare
            #print(nfc_tag_list['nfc_tag_list'])
            #print('now')
            nfc_tag_list = nfc_tag_list['nfc_tag_list']
            #print(nfc_tag_list[0])
            #print(nfc_tag_list[1])
            #print(nfc_tag_list[2])
            #print(nfc_tag_list[0]['nfc_tag'])
            for u in nfc_tag_list:
                if u['nfc_tag'] == nfc_tag:
                    print('nfc tagg machted')
                    access_flag = True

            ###nfc_tag_list = json.dumps(nfc_tag_list)
            ###print(nfc_tag_list)

            #if 'nfc_tag' in nfc_tag_list:
            #    print('found nfc_tag in nfc_tag_list')
            #    for c in nfc_tag_list['nfc_tag']:
            #        if c == nfc_tag:
            #            print('nfc_tag mached')
            #            break;
                    #found = models.DoorAccesControll.objects.all()#filter(data__icontains='"nfc_tag": "{}"'.format(nfc_tag))

            #print(found)
            #print(ObtainAuthToken().post(request))
            #for i in user.nfc_tag_list[].length
                #if nfc_tag == user.nfc_tag_list[i]
                    #access_flag = True
            #items = Item.objects.filter(acct__active=1, acct__user=request.user)
            #print(items)
            #print(nfc_tag+"==serializer.data.get('nfc_tag')")
            return Response({'access_flag':access_flag})

        else:
            print('serializer not valid')
            return Response(serializer.errors,
            status = status.HTTP_400_BAD_REQUEST)
