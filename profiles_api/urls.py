from django.urls import path, include

from rest_framework.routers import DefaultRouter
from . import views as profiles_api_views

router = DefaultRouter()
router.register('Hello-viewset', profiles_api_views.HelloViewSet, base_name='hello-viewset')


urlpatterns = [
    path('hello-view', profiles_api_views.HelloApiView.as_view()),
    path('',include(router.urls))
]
