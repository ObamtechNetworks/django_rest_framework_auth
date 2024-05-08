from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    """Handles the user properties

    Args:
        BaseUserManager (extends the custom user): extends with django base user manage property
    """
    def email_validator(self, email):
        """validates user's email

        Args:
            email (str): a user email string
        """
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("please enter a valid email address"))
        
    def create_user(self, email, first_name, last_name, password, **extra_fields):
        """creates the user for us

        Args:
            email (str): user's email
            first_name (str): user's first name
            last_name (str): user's last name
            password (str): user's secret password
        """
        # check if email is provided
        if email:
            email = self.normalize_email(email)  # normalizes the user's email
            self.email_validator(email)
        else:
            raise ValueError(_("An email address is required"))
        if not first_name:
            raise ValueError(_("First name is required"))
        if not last_name:
            raise ValueError(_("Last name is required"))
        
        # if all above is provided then let's create user first without the password
        user = self.model(email=email, first_name=first_name, last_name=last_name, **extra_fields)
        # set the password by hashing
        user.set_password(password)
        # save user
        user.save(using=self._db)
        return user
    
    # create super user
    def create_superuser(self, email, first_name, last_name, password, **extra_fields):
        """creates a super user

        Args:
            email (str): super user email
            first_name (str): super user first name
            last_name (str): super user last name
            password (str): super user's secret password
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)
        
        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("is staff must be true for admin user"))
        
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("is superuser must be true for admin user"))
        
        user = self.create_user(
            email, first_name, last_name, password, **extra_fields
        )
        user.save(using=self._db)