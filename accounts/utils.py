# function to generate OTP and send email
# there are different approaches e.g a shortlived otp, to use python package pyotp ( this expires at a particular time)
# what we want is just a simple otp verification

import random
from django.core.mail import EmailMessage
from .models import User, OneTimePassword
from django_rest_auth import settings

def generateOTP():
    """generates a random OTP
    """
    otp = ""
    for i in range(6):
        otp += str(random.randint(1, 9))
    return otp

def send_code_to_user(email):
    """send otp code to user's email

    Args:
        email (str): user's email
    """
    Subject = "One Time passcode for Email Verification"
    otp_code = generateOTP()
    print(otp_code)
    user = User.objects.get(email=email)
    current_site = "myauth.com" # front end domain
    email_body = f"""
                Hi {user.first_name}! Thank you for signing up on {current_site}
                please use the passcode below to complete registration:
                passcode: {otp_code}
                """
    from_email = settings.DEFAULT_FROM_EMAIL
    
    OneTimePassword.objects.create(user=user, code=otp_code)
    d_email = EmailMessage(subject=Subject, body=email_body, from_email=from_email, to=[email])
    d_email.send(fail_silently=True)
    

def send_normal_email(data):
    """sends email

    Args:
        data (dict): use the data to send a mail
    """
    email = EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()