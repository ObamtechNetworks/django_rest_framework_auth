from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from .manager import UserManager
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.


AUTH_PROVIDERS = {'email':'email', 'google':'google', 'github':'github', 'facebook':'facebook'}

class User(AbstractBaseUser, PermissionsMixin):
    """Create a custom User class

    Args:
        AbstractBaseUser (class): extends its functionality for the User class
        PermissionsMixin (class): extends permission functionality for user
    """
    email = models.EmailField(max_length=255, unique=True, verbose_name=_("Email Address"))
    first_name = models.CharField(max_length=255, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=255, verbose_name=("Last Name"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(max_length=50, default=AUTH_PROVIDERS.get('email'))
    
    USERNAME_FIELD = 'email'
    
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    objects = UserManager()
    
    def __str__(self):
        """returns the user email as string
        """
        return self.email
    
    @property
    def get_full_name(self):
        """returns the user's full name
        """
        return f"{self.first_name} {self.last_name}"
    
    def tokens(self):
        """generates token
        """
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    
    
class OneTimePassword(models.Model):
    """one time password model for saving otp into data for each specific user

    Args:
        models (class): extends the django class model
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, unique=True)
    
    def __str__(self):
        return f"{self.user.first_name}-passcode"
    