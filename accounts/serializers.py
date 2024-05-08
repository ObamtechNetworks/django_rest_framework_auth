from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.serializers import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, force_bytes, force_str
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class UserRegisterSerializer(serializers.ModelSerializer):
    """serializes json data for the user

    Args:
        serializers (class): rest_framework serializer class
    """
    password = serializers.CharField(max_length=68, min_length=8, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=8, write_only=True)
    
    # create the metadata 
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']
        
    def validate(self, attrs):
        """method to validate data

        Args:
            attrs (dict): key value pair containing attributes to check and set
        """
        # to compare the two passwords provided by the user
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password != password2:
            raise serializers.ValidationError("passwords does not match")
        return super().validate(attrs)
    
    def create(self, validated_data):
        """create the serialized user

        Args:
            validated_data (dict): keyvalue pair data that has been validated
        """
        # we need to individually pass the data so as to omit the second password validation
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        return user
    

class LoginSerializer(serializers.ModelSerializer):
    """serializes user login data

    Args:
        serializers (class): django rest_framework serializer class
    """
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=68, min_length=8, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']
        
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credentials try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        user_token = user.tokens()
        return {
            'email': user.email, 
            'full_name': user.get_full_name,
            'access_token': str(user_token.get('access')),
            'refresh_token': str(user_token.get('refresh'))
        }
        
class PasswordResetRequestSerializer(serializers.Serializer):
    """password resetting

    Args:
        serializers (class): extends serial function to model
    """
    email = serializers.EmailField(max_length=255)
    
    # class Meta:
    #     fields = ['email']
        
    class Meta:
        fields = ['email']
        
    def validate(self, attrs):
        email = attrs.get('email')
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No user found with this email.")
        # if email exists, then proceed below
        user = User.objects.get(email=email)
        # Encode the user id
        uidb64 = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        request = self.context.get('request')
        site_domain = get_current_site(request).domain
        relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
        absolute_link = f"http://{site_domain}{relative_link}"
        email_body = f"Hi, use the link below to reset your password:\n{absolute_link}"
        data = {
            'email_body': email_body,
            'email_subject': "Reset your Password",
            'to_email': user.email
        }
        # Send the password reset email
        send_normal_email(data)
        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')

            # decode the uidb64
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Reset link is invalid or has expired")

            # Check for password mismatch
            if password != confirm_password:
                raise serializers.ValidationError({"password": "Passwords do not match"})

            user.set_password(password)
            user.save()

            return user
        except ValidationError:
            raise ValidationError({"password": "Passwords do not match"})
        except Exception as e:
            raise AuthenticationFailed("An unexpected error occurred. Invalid or expired token")



class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    
    default_error_messages = {
        'bad_token': ('Token is invalid or has expired')
    }
    
    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs
    
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()  # black teh token
        except TokenError:
            return self.fail('bad_token')