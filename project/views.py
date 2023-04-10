from django.contrib.auth.models import User 
from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.decorators import login_required  
from django.contrib.auth import authenticate, login, logout   
import json 
import requests 

@login_required(login_url='login') 
def home(request):
  return render(request, 'Dashboard.html')  

def register(request):   
  if request.method =='POST':  
      uname=request.POST.get('username') 
      email=request.POST.get('email') 
      pass1=request.POST.get('password1')    
      pass2=request.POST.get('password2')  

      if pass1!=pass2: 
        messages.error("Нууц үг таарахгүй байна!!!") 
      else: 
        my_user=User.objects.create_user(uname,email,pass1) 
        my_user.save() 
        return redirect('login')
  return render(request, 'register.html')

def LoginPage(request):  
  if request.method=='POST': 
      username=request.POST.get('username') 
      pass1=request.POST.get('pass') 
      user=authenticate(request, username=username, password=pass1) 
      if user is not None: 
          login(request, user) 
          return redirect('home') 
      else:  
          messages.error(request, "Нэвтрэх нэр, нууц үг буруу байна")

  return render(request, 'login.html')  

def Logout(request): 
  logout(request) 
  return redirect('login') 

@login_required(login_url='login') 
def Ipgeo(request):   
  ip = requests.get('https://api.ipify.org?format=json')   
  ip_data = json.loads(ip.text)   
  res = requests.get('http://ip-api.com/json/'+ip_data["ip"]) 
  location_data_one = res.text 
  location_data = json.loads(location_data_one)
  if request.POST.get('Theip'):   
      ip_data = str(request.POST.get('Theip'))   
      res = requests.get('http://ip-api.com/json/'+ip_data) 
      location_data_one = res.text 
      location_data = json.loads(location_data_one)
  return render(request, 'ipgeo.html', { 'data' : location_data })


