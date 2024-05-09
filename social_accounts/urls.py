from django.urls import path
from .views import GoogleSignInvView

urlpatterns = [
    path('google/', GoogleSignInvView.as_view(), name='google'),
]
