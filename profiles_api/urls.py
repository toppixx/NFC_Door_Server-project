from django.urls import path, include

from rest_framework.routers import DefaultRouter
from . import views as profiles_api_views

router = DefaultRouter()
router.register('Hello-viewset', profiles_api_views.HelloViewSet, base_name='hello-viewset')
router.register('create-user', profiles_api_views.CreateNewUserViewSet,base_name='create-user')
router.register('profile', profiles_api_views.UserProfileViewSet)
router.register('login', profiles_api_views.LoginViewSet, base_name='login')
router.register('feed', profiles_api_views.UserProfileFeedViewSet)
router.register('access', profiles_api_views.DoorAccesControllViewSet)

urlpatterns = [
    path('hello-view', profiles_api_views.HelloApiView.as_view()),
    path('',include(router.urls))
]
