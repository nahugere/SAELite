from django.urls import path, include
from . import views as v

urlpatterns = [
    path("", v.home, name="home"),
    path("file/", v.allege, name="file"),
    path("s/", v.search_employees, name="search"),
]
