from django.contrib.auth.models import User 
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required  
from django.contrib.auth import authenticate, login, logout   
import json, requests, geocoder, folium  
from django.http import HttpResponse
from django.http.response import JsonResponse

from django.views.generic import CreateView, UpdateView, DeleteView, ListView, DetailView

from .forms import ScannerForm

from .models import (
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory
)

from django.urls import reverse_lazy, reverse, resolve
from django.views import View

from .scanners import NmapScanner, ScapyScanner

from django.db.models import F

import json

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
    g = geocoder.ip('me')
    myAddress = g.latlng 
    my_map1 = folium.Map(location=myAddress,zoom_start=12) 
    folium.CircleMarker(location=myAddress, radius=50, popup="Yorkshire").add_to(my_map1)
    folium.Marker(myAddress, popup="Yorkshire").add_to(my_map1)
    if request.POST.get('Theip'):  
        ip_data =str(request.POST.get('Theip')) 
        res = requests.get('http://ip-api.com/json/'+ip_data) 
        location_data_one = res.text 
        location_data = json.loads(location_data_one)
        g = geocoder.ip(ip_data)  
        myAddress = g.latlng  
        my_map1 = folium.Map(location=myAddress,zoom_start=12) 
        folium.CircleMarker(location=myAddress, radius=50, popup="Yorkshire").add_to(my_map1)
        folium.Marker(myAddress, popup="Yorkshire").add_to(my_map1)  
    m = my_map1._repr_html_()  
    return render(request, 'ipgeo.html', {'map': m, 'data' : location_data}) 

class ScannerView(View, NmapScanner, ScapyScanner):

    model = ScannerHistory
    template_name = "scanner_form.html"

    def get(self, request) :

        scanner_form = ScannerForm()

        context = {
            'scanner_form': scanner_form
        }

        return render(request, self.template_name, context)

    def post(self, request) :

        target = request.POST['target']
        type = request.POST['type']
        response = {}

        if type == 'QS':
            self.target = target
            self.save_quick_scan()
            response['success'] = True
        else:
            self.perform_full_scan_and_save(request.POST['target'])
            response['success'] = True

        return HttpResponse(json.dumps(response), content_type="application/json")
        

class ScannerHistoryListView(ListView):

    model = ScannerHistory
    template_name = "scanner_history_list.html"

    def get(self, request, type) :

        scanner_history = ScannerHistory.objects.filter(type=type)

        context = {
            'scanner_history' : scanner_history
        }
        return render(request, self.template_name, context)

class HostListView(ListView):

    model = Host
    template_name = "scanner_history_host_list.html"

    def get(self, request, scanner_history_id):

        scanner_history = ScannerHistory.objects.get(pk=scanner_history_id)

        hosts = Host.objects.filter(host_history=scanner_history_id)

        context = {
            'hosts' : hosts,
            'scanner_history': scanner_history
        }
        return render(request, self.template_name, context)

class OperativeSystemMatchListView(ListView):

    model = OperativeSystemMatch
    template_name = "scanner_history_host_os_matches_list.html"

    def get(self, request, scanner_history_id, host_id):

        host = Host.objects.get(pk=host_id)

        """
        Denormalizing tables

        INNER JOIN, source: 
        https://stackoverflow.com/a/21360352/9655579

        Set alias for fields, source: 
        https://stackoverflow.com/a/46471483/9655579
        """
        operative_system_match = OperativeSystemMatch.objects.filter(
            host=host_id
        ).values(
            'id',
            'name',
            'accuracy',
            'line',
            'created_on',
            'os_match_class__type',
            'os_match_class__vendor',
            'os_match_class__operative_system_family',
            'os_match_class__operative_system_generation',
            'os_match_class__accuracy'
        ).annotate(
            os_id=F('id'),
            os_name=F('name'),
            os_accuracy=F('accuracy'),
            os_line=F('line'),
            os_created_on=F('created_on'),
            os_match_class_type=F('os_match_class__type'),
            os_match_class_vendor=F('os_match_class__vendor'),
            os_match_class_operative_system_family=F('os_match_class__operative_system_family'),
            os_match_class_operative_system_generation=F('os_match_class__operative_system_generation'),
            os_match_class_accuracy=F('os_match_class__accuracy'),
        )

        context = {
            'operative_system_matches' : operative_system_match,
            'host': host,
            'scanner_history_id': scanner_history_id
        }

        return render(request, self.template_name, context)


class PortListView(ListView):

    model = Port
    template_name = "scanner_history_host_ports.html"

    def get(self, request, scanner_history_id, host_id):

        host = Host.objects.get(pk=host_id)

        """
        Denormalizing tables

        INNER JOIN, source: 
        https://stackoverflow.com/a/21360352/9655579

        Set alias for fields, source: 
        https://stackoverflow.com/a/46471483/9655579
        """
        ports = Port.objects.filter(
            host=host_id
        ).values(
            'id',
            'protocol',
            'portid',
            'state',
            'reason',
            'reason_ttl',
            'created_on',
            'port_service__name',
            'port_service__product',
            'port_service__extra_info',
            'port_service__hostname',
            'port_service__operative_system_type',
            'port_service__method',
            'port_service__conf'
        ).annotate(
            port_id=F('id'),
            port_name=F('protocol'),
            port_accuracy=F('portid'),
            port_state=F('state'),
            port_reason=F('reason'),
            port_reason_ttl=F('reason_ttl'),
            port_created_on=F('created_on'),
            port_service_name=F('port_service__name'),
            port_service_product=F('port_service__product'),
            port_service_extra_info=F('port_service__extra_info'),
            port_service_hostname=F('port_service__hostname'),
            port_service_operative_system_type=F('port_service__operative_system_type'),
            port_service_method=F('port_service__method'),
            port_service_conf=F('port_service__conf'),
        )

        context = {
            'ports' : ports,
            'host': host,
            'scanner_history_id': scanner_history_id
        }

        return render(request, self.template_name, context) 
 
def Domain(request): 
    return render(request, 'domain.html')

