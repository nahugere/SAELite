from django.http import JsonResponse
from django.shortcuts import render
from .models import *
from . import utils

def home(request):
    employees = Personnel.objects.all()[0:10]
    if request.method == "POST":
        p = Personnel.objects.get(employee_id=request.POST.get('selected_person'))
        pk = p.ca.rsa_public_key
        message = request.POST.get("cert")
        signature = Certificate.objects.get(personnel=p).signature
        verified = utils.verify_cert(pk, message, signature)
        return render(request, "core/home.html", {"people": employees, "show_message": True})
    return render(request, "core/home.html", {"people": employees, "verified": verified})

def allege(request):
    employees = Personnel.objects.all()[0:10]
    return render(request, "core/filing.html", {"people": employees})