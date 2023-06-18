from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.core.mail import send_mail
import random
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
from django.utils.crypto import get_random_string
from LoginPage.models import OTP
from LoginPage.models import User
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.template.loader import render_to_string



# def login_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')
#         user = authenticate(request, email=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect('register')  # Redirect to the home page or any other desired page
#         else:
#             return render(request, 'login.html', {'error': 'Invalid email or password'})

#     return render(request, 'login.html')

def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            # User credentials are valid, log the user in
            login(request, user)
            return redirect('dashboard')  # Redirect to the dashboard or any other desired page
        
        else:
            # Invalid user credentials, display an error message
            error = "Invalid email or password"
            return render(request, 'login.html', {'error': error})
    
    return render(request, 'login.html')

def dashboard_view(request):
    return render(request, 'dashboard.html')


def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful'}, status=200)


def home_view(request):
    return render(request, 'home.html')


# def send_otp_email(request, user):
#     current_site = get_current_site(request)
#     mail_subject = 'OTP Verification'
#     otp = default_token_generator.make_token(user)
#     otp_secret = otp[:6]  # Extract the first 6 characters of the OTP

#     # Save the OTP secret in the database
#     otp_obj, created = OTP.objects.get_or_create(user=user)
#     otp_obj.otp_secret = otp_secret
#     otp_obj.save()

#     message = f'Your OTP code is: {otp_secret}\n\n' \
#               f'Please enter this code to verify your account on {current_site.domain}'

#     send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

def generate_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp_secret = get_random_string(length=6, allowed_chars='0123456789')
        current_site = get_current_site(request)
        print("otp==>",otp_secret)
        mail_subject = 'OTP Verification'
        message = f'Your OTP code is: {otp_secret}\n\n' \
                  f'Please enter this code to verify your account on {current_site.domain}'
        print("===mail",current_site.domain)
        try:
            send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            return HttpResponse("OTP has been sent to your email.")
        except:
            print("err==>")
            return HttpResponse("Failed to send OTP. Please try again later.")
    else:
        return HttpResponse("Invalid request method.")


# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         email = request.POST.get('email')
#         password = request.POST.get('password')
#         phone = request.POST.get('phone')

#         # Create the user
#         user = User.objects.create_user(username=username, email=email, password=password)
#         user.save()

#         # Send OTP to the user's email
#         send_otp_email(request, user)

#         messages.success(request, 'OTP has been sent to your email.')  # Add success message

#         return redirect('verify_otp')
#     else:
#         return render(request, 'register.html')

# from .models import User  # Import the custom User model from your app



def register_view(request):
    if request.method == 'POST':
        # Retrieve form data
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        
        try:
            # Check if the user already exists
            existing_user = User.objects.get(username=username)
            error_message = f"Username '{username}' already exists. Please choose a different username."
            messages.error(request, error_message)
            return redirect('register')
        except User.DoesNotExist:
            # Create a new user
            user = User.objects.create_user(username=username, email=email, password=password)
            
            # Additional logic...
            
            return redirect('login')  # Redirect to the login page or any other desired page
    
    return render(request, 'register.html')
