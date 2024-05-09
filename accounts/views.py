from django.shortcuts import render
from .serializers import (UserRegisterSerializer,
                          LoginSerializer, PasswordResetRequestSerializer,
                          SetNewPasswordSerializer,
                          LogoutUserSerializer)
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .utils import send_code_to_user
from .models import OneTimePassword, User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# Create your views here.
# create endpoints below
class RegisterUserView(GenericAPIView):
    """the config for the register endpoint for our api

    Args:
        GenericAPIView (clas): generic api from rest_framework
    """
    serializer_class = UserRegisterSerializer
    
    # define a post method
    def post(self, request):
        """a post request to be processed for the register endpoint
        sends an email to the user after registeration

        Args:
            request (method): request method to fetch data
        """
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        # check if serialized data from user data is valid
        if serializer.is_valid(raise_exception=True):
            # if valid save the data
            serializer.save()
            user = serializer.data
            # send email function user['emial']  # utils module
            send_code_to_user(user['email'])
            return Response({
                'data': user,
                'message': f"Hi {user.get('first_name')} thanks for signing up, a passcode has been sent to your mail, use it to complete your registration ..."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyUserEmail(GenericAPIView):
    """verifies user email based on the otp code sent

    Args:
        GenericAPIView (class): extends class based on rest_framework
    """
    def post(self, request):
        """sends a post request to verify user using the otp

        Args:
            request (method): sends a request
        """
        otpcode = request.data.get('otp')
        try:
            user_code_obj = OneTimePassword.objects.get(code=otpcode)
            user = user_code_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message': 'account email verified successfully'
                }, status=status.HTTP_200_OK)
            return Response({
                'message':'code is invalid user already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({
                'message': 'passcode not provided'
            }, status=status.HTTP_404_NOT_FOUND)
            

class LoginUserView(GenericAPIView):
    """handles login endpoint

    Args:
        GenericAPIView (class): generic apiview
    """
    serializer_class = LoginSerializer
    
    def post(self, request):
        """sends a post request and process user's login

        Args:
            request (method): sends a post request
        """
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        data = {
            'msg': 'It works'
        }
        return Response(data, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        # Assuming 'email' is a field in your serializer
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        return Response({
            'message': f'A link has been sent to {email} to reset your password.'
        }, status=status.HTTP_200_OK)
        
# from frontend, when user clicks on the reset password link, it will take them to route to this view 
class PasswordResetConfirm(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            # first extract the user id
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({
                    'message': 'token is invalid or has expired'
                }, status=status.HTTP_401_UNAUTHORIZED)
            return Response({
                'success': True,
                'message': 'crendentials is valid',
                'uidb64': uidb64,
                'token':token
            }, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({
                    'message': 'token is invalid or has expired'
                }, status=status.HTTP_401_UNAUTHORIZED)

# after confirming password, this view is shown to set new password
class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    # send a patch request
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # serializer.validate(serializer.data)
        return Response({
            'message': 'password has been reset successfully'
        }, status=status.HTTP_200_OK)
        

class LogoutUserView(GenericAPIView):
    serializer_class = LogoutUserSerializer
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'success': 'You have been logged out successfully'}, status=status.HTTP_204_NO_CONTENT)