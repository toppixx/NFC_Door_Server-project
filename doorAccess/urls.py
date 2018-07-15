from django.urls import path, include

from rest_framework.routers import DefaultRouter
from . import views as doorAccews_views

router = DefaultRouter()
router.register('Hello-viewset', doorAccews_views.HelloViewSet, base_name='hello-viewset')
router.register('create-user', doorAccews_views.CreateNewUserViewSet,base_name='create-user')
router.register('profile', doorAccews_views.UserProfileViewSet)
router.register('login', doorAccews_views.LoginViewSet, base_name='login')
router.register('feed', doorAccews_views.UserProfileFeedViewSet)
router.register('access', doorAccews_views.DoorAccesControllViewSet)
router.register('NFCDoorAcContPhase1', doorAccews_views.NfcDooorAcContPhase1ViewSet, base_name='NfcDACP1')
router.register('NFCDoorAcContPhase2', doorAccews_views.NfcDooorAcContPhase2ViewSet, base_name='NfcDACP2')
router.register('NFCDoorAcContPhase3', doorAccews_views.NfcDooorAcContPhase3ViewSet, base_name='NfcDACP3')
urlpatterns = [
    path('hello-view', doorAccews_views.HelloApiView.as_view()),
    path('',include(router.urls))
]
