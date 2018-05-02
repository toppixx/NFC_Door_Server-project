from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets

from . import serializers

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

    def list(self, request):
        """ Return a Hello Message. """
        a_viewset = [
        'ueses actions (list, create, retrieve, update, partial_update)',
        'Automaticaly mapps to URLs using Routers',
        'Provides more functionality with less code.',
        ]

        return Response({'message':'Hello', 'a_viewset': a_viewset})

    def create(self, request):

        return Response({'message':'create' })

    def retrieve(self, request):

        return Response({'message':'retrieve' })

    def update(self, request):

        return Response({'message':'update' })

    def partial_update(self, request):

        return Response({'message':'partial_update' })
