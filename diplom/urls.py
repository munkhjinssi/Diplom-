"""diplom URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from project import views  
 
app_name = 'diplom'
urlpatterns = [ 
    path('admin/', admin.site.urls),      
    path('home/', views.home, name="home"),  
    path('register/', views.register, name="register"), 
    path('', views.LoginPage, name="login"), 
    path('logout/', views.Logout, name='logout'),  
    path('ipgeo/', views.Ipgeo, name='ipgeo'),  
    path('domain/', views.Domain, name="domain"), 
    path('network-scanner/', views.ScannerView.as_view(), name='form_scanner_view'),
    path('perform-scan/', views.ScannerView.as_view(), name='post_form_scanner'),
    path('scanner-history/<str:type>', views.ScannerHistoryListView.as_view(), name='scanner_type'), 
    path('delete/<int:pk>', views.delete, name="delete"),
    path('scanner-history/<int:scanner_history_id>/host', views.HostListView.as_view(), name='host_list'),
    path('scanner-history/<int:scanner_history_id>/host/<int:host_id>/os_match', views.OperativeSystemMatchListView.as_view(), name='os_matches_list'),
    path('scanner-history/<int:scanner_history_id>/host/<int:host_id>/ports', views.PortListView.as_view(), name='host_ports_list'),  
    path('domain/', views.Domain, name="domain"), 
    path('storing/', views.Store, name="storing"),   
    path('stored/', views.retrieve, name="stored") , 
    path('ipgeo/storingip/', views.StoreIPData, name="storingip"), 
    path('stored/delete/', views.delete_history, name="delete-history")
]
