from django.urls import path, include
from . import views as profiles_api_views
urlpatterns = [
    path('hello-view', profiles_api_views.HelloApiView.as_view()),
]
