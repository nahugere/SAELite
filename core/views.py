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
        verified, pairings = utils.verify_cert(pk, message, signature)
        return render(request, "core/home.html", {"people": employees, "show_message": True, "verified": verified, "pairings": pairings})
    return render(request, "core/home.html", {"people": employees, "show_message": False, "verified": False})

def search_employees(request):
    e = request.GET.get("employee", None)
    if e:
        emp = Personnel.objects.filter(full_name__contains=e)[0:10]
        employees = [{"fullname": x.full_name, "position":x.position, "id":x.employee_id} for x in emp]
        return JsonResponse({"people": employees}, safe=False)
    emp = Personnel.objects.all()[0:10]
    employees = [{"fullname": x.full_name, "position":x.position, "id":x.employee_id} for x in emp]
    return JsonResponse({"people": employees}, safe=False)

def allege(request):
    employees = Personnel.objects.all()[0:10]
    return render(request, "core/filing.html", {"people": employees})