from django.shortcuts import render,redirect,reverse
from .models import Traveler

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
import re
from django.contrib.auth import get_user_model
from django.contrib.auth import logout

User = get_user_model()



def validate_password(password):
    # Define regular expression patterns for required characters
    required_char_patterns = {
        'uppercase': r'[A-Z]',
        'lowercase': r'[a-z]',
        # 'digit': r'[0-9]',
        'special': r'[!@#$%^&*()_+-]'
    }
    # Check if the password contains all required characters
    for char_type, pattern in required_char_patterns.items():
        if not re.search(pattern, password):
            return False
    # If all required characters are present, return True
    return True

def full_name_is_valid(full_name):
    # Define your full name format check here
    # This could be a regex match, string length check, etc.
    if len(full_name) < 3 or len(full_name) > 255:
        return False
    if not full_name.strip():
        return False
    return True

def SignUp(request):
    if request.method == 'POST':
        form = request.POST
        fullname = form.get('fullname')
        username = request.POST.get('user_name')
        password = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        if not full_name_is_valid(fullname):
            # Full name does not meet the format
            messages.error(request, f'Fullname should be "Firstname Middlename Lastname" ')
            return render(request, 'signup.html')

        if len(username) < 7:
            messages.error(request, 'Username must be more than 7 character')
            return render(request, 'signup.html')

        username_exit = User.objects.filter(username=username).exists()
        if username_exit:
            messages.error(request, 'Username already taken')
            return render(request, 'signup.html')

        if not validate_password(password):
            messages.error(request, 'Password must contain at least one uppercase letter, one lowercase letter and one special character.')
            return render(request, 'signup.html')

        if password != password2:
            messages.error(request, 'password does not match')
            return render(request, 'signup.html')
        
        # Create user object
        user = User.objects.create_user(username=username, password=password)

        # Create traveler object        
        my_Traveler = Traveler.objects.create(user=user, full_name = fullname)
        # my_Traveler.set_password(password)
        my_Traveler.save()
        messages.success(request, f'You are succesfully login as {username}')
        return redirect(reverse('LoginPage'))            

    return render(request, 'signup.html')



def LoginPage(request):
    if request.method == 'POST':               
        # Login
        Username = request.POST.get('username')
        Password = request.POST.get('password')

        # Authenticate user
        user = authenticate(username=Username, password=Password)
        if user is not None:
            # User is valid
            login(request, user)
            messages.success(request, f'You have been logged in as {Username}')
            return redirect(reverse('Dashboard'))
        else:
            # Invalid user credentials
            messages.error(request, 'Invalid username or password')
    return render(request, 'login-copy.html')


def Dashboard(request):
    user = request.user
    if request.user.is_authenticated:
        username = request.POST.get('username')
        user_exist = User.objects.filter(username=username).exists()
        # if user_exist:
        user = Traveler.objects.get(user=user)
        # username =  Traveler.objects.get(username=username)
            
        context = {
            "user" : user
        }
    return render(request, 'dashboard.html', context)



def logout_request(request):
	logout(request)
	messages.info(request, "You have successfully logged out.") 
	return redirect("HomePage")


'''
def LoginPage(request):
    is_login = request.method == 'POST' and 'username' in request.POST
    signup_active = not is_login

    if request.method == 'POST':
        form_data = {
            'fullname': request.POST.get('fullname'),
            'username': request.POST.get('username'),
            'password': request.POST.get('password1'),
            'password2': request.POST.get('password2'),
        }

        if is_login:
            # Login logic
            user = authenticate(username=form_data['username'], password=form_data['password'])
            if user is not None:
            # User is valid
                login(request, user)
                messages.success(request, f'You have been logged in as {username}')
                return redirect(reverse('Dashboard'))

        else:
            # Signup logic
            
            if not validate_fullname(form_data['fullname']):
                messages.error(request, f'Fullname should be "Firstname Middlename Lastname" ')
                # return render(request, 'login-copy.html')
                
            if len(form_data['username']) < 7:
                messages.error(request, 'Username must be more than 7 character')
                return render(request, 'login-copy.html')
            username_exit = User.objects.filter(username=username).exists()
            if username_exit:
                messages.error(request, 'Username already taken')
                # return render(request, 'login-copy.html')

            if not validate_password(form_data['password']):
                messages.error(request, 'Password must contain at least one uppercase letter, one lowercase letter and one special character.')
                # return render(request, 'login-copy.html')

            if password != password2:
                messages.error(request, 'password does not match')
                # return render(request, 'login-copy.html')
        
            # Create user object
            user = User.objects.create_user(username=username, password=password)

            # Create traveler object        
            my_Traveler = Traveler.objects.create(user=user, full_name = fullname)
            # my_Traveler.set_password(password)
            my_Traveler.save()
            messages.success(request, f'You are succesfully login as {username}')
            return redirect(reverse('Dashboard'))
            

    context = {
        'is_login': is_login,
        'signup_active': signup_active,
    }
    return render(request, 'login_signup.html', context)
'''
'''
def LoginPage(request):
    is_login = request.method == 'POST' and 'username' in request.POST
    signup_active = not is_login

    context = {
        'is_login': is_login,
        'signup_active': signup_active,
    }

    if request.method == 'POST':
        form_data = {
            'fullname': request.POST.get('fullname'),
            'username': request.POST.get('username'),
            'password': request.POST.get('password1'),
            'password2': request.POST.get('password2'),
        }

        if is_login:
            # Login logic
            if not request.user.is_authenticated:
                user = authenticate(username=form_data['username'], password=form_data['password'])
                if user is not None:
                    login(request, user)
                    messages.success(request, f'You have been logged in as {username}')
                    return redirect(reverse('Dashboard'))
                else:
                    messages.error(request, 'Invalid username or password')
                    return render(request, 'login-copy.html', context)
        else:
            # Signup logic
            if not full_name_is_valid(form_data['fullname']):
                messages.error(request, f'Fullname should be "Firstname Middlename Lastname" ')
                return render(request, 'login-copy.html', context)
                
            # if len(form_data['username']) < 7:
            #     messages.error(request, 'Username must be more than 7 character')
            #     return render(request, 'login-copy.html')
            username_exit = User.objects.filter(username=form_data['username']).exists()
            if username_exit:
                messages.error(request, 'Username already taken')
                return render(request, 'login-copy.html')

            if not validate_password(form_data['password']):
                messages.error(request, 'Password must contain at least one uppercase letter, one lowercase letter and one special character.')
                return render(request, 'login-copy.html')

            if form_data['password'] != form_data['password2']:
                messages.error(request, 'password does not match')
                return render(request, 'login-copy.html')

            # Create user and traveler objects only if signup is successful
            user = User.objects.create_user(username=form_data['username'], password=form_data['password'])
            my_Traveler = Traveler.objects.create(user=user, full_name=form_data['fullname'])
            my_Traveler.save()
            messages.success(request, f'Welcome aboard, {username}! You are now registered.')
            return redirect(reverse('Dashboard'))

    
    return render(request, 'login-copy.html', context)
    '''

