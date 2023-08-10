from django.urls import path, include
from . import views
urlpatterns = [
    path('', views.home),
    path('encrypted/', views.home2),
    path('encrypted/text/', views.txtencrypt),
    path('encrypted/image/', views.imgencrypt),
]
