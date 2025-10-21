from django.shortcuts import render

def home(request):
    
    return render("core/home.html")
