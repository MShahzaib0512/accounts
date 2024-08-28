from django.shortcuts import render , redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate , login , logout
from pools import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from . tokens import *
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode , urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

# Create your views here.
def home(request):
 return render(request , 'home.html')

def signup(request):
 if request.method == 'POST':
  uname = request.POST['uname']
  fname = request.POST['fname']
  lname = request.POST['lname']
  email = request.POST['email']
  pass1 = request.POST['pass1']
  pass2 = request.POST['pass2']
  
  if User.objects.filter(username = uname):
    messages.error(request , "Username Already taken!", extra_tags='username_error')
    return redirect ('signup')
  
  elif User.objects.filter(email = email):
    messages.error(request , "Email Already taken!" , extra_tags='email_error')
    return redirect ('signup')
  
  elif pass1 != pass2 :
    messages.error(request , "Password not mached", extra_tags='passsword_error')
    return redirect ('signup')
  
  elif not uname.isalnum():
    messages.error(request , "Username invalid!", extra_tags='usernmae_error')
    return redirect ('signup')
  elif len(str(pass1)) < 8:
     messages.error(request , "Password must be of Eight characters!", extra_tags='usernmae_error')
     return redirect ('signup')
  else:
    myuser = User.objects.create_user(uname , email , pass1)
    myuser.first_name= fname
    myuser.last_name = lname
    myuser.is_active = False
    myuser.save()
      
    site = get_current_site(request)
    # welcome mail
    subject = 'Confermation Email!'
    message = render_to_string('confermation_Email.html',{
      'user'  : myuser.first_name,
      'domain': site.domain,
      'uid'   : urlsafe_base64_encode(force_bytes(myuser.pk)),
      'token' : generate_token.make_token(myuser),
      })
    from_email = settings.EMAIL_HOST_USER
    to_list =[myuser.email]
    send_mail(subject , message , from_email , to_list, fail_silently = True)
    
    
    messages.success(request , "your account have been created successfully!! Please confirm your Email address to activate your account " , extra_tags="alert_success")
    return redirect('signin')
 return render( request , 'signup.html')

def signin(request):
  if request.method== 'POST':
    uname = request.POST['uname']
    pass1 = request.POST['pass1']
    
    user = authenticate(username = uname , password = pass1)
    
    if user is not None:
      login(request , user)
      fname = user.first_name
      return render(request, "signout.html" , {'fname': fname})
    else:
      messages.error(request , "invalid Email / password !!!" , extra_tags="alert_danger")  
      return redirect('signin')
  return render(request , 'signin.html')

def signout(request):
  logout(request)
  return render(request , 'home.html')

def activate(request , uidb64 , token):
  try:
    uid = force_str(urlsafe_base64_decode(uidb64))
    myuser = User.objects.get(pk = uid)
  except(TypeError, ValueError, User.DoesNotExist):
    myuser = None
    
  if myuser is not None and generate_token.check_token(myuser, token):
    myuser.is_active=True
    myuser.save()
    login(request, myuser)
    return redirect('signin')
  else:
    return render (request , 'activation_failed.html')
    