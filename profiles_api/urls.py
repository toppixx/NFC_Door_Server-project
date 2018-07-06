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
router.register('NFCDoorAcContPhase1', profiles_api_views.NfcDooorAcContPhase1ViewSet, base_name='NfcDACP1')
router.register('NFCDoorAcContPhase2', profiles_api_views.NfcDooorAcContPhase2ViewSet, base_name='NfcDACP2')
router.register('NFCDoorAcContPhase3', profiles_api_views.NfcDooorAcContPhase3ViewSet, base_name='NfcDACP3')
urlpatterns = [
    path('hello-view', profiles_api_views.HelloApiView.as_view()),
    path('',include(router.urls))
]
