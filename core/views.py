from django.core.exceptions import ObjectDoesNotExist, SuspiciousOperation
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import *
from . import utils

def home(request):
    employees = Personnel.objects.all()[0:10]
    if request.method == "POST":
        # try:
        p = Personnel.objects.get(employee_id=request.POST.get('selected_person'))
        pk = p.ca.rsa_public_key
        message = request.POST.get("cert")
        signature = Certificate.objects.get(personnel=p).signature
        verified, pairings = utils.verify_cert(pk, message, signature)
        return render(request, "core/home.html", {"people": employees, "show_message": True, "verified": verified, "pairings": pairings})
        # except Exception:
            # return render(request, "core/home.html", {"people": employees, "show_message": True, "verified": False})
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

@csrf_exempt
def allege(request):
    employees = Personnel.objects.all()[0:10]
    if request.method == "POST":
        pk = request.POST.get("public_key")
        mac_key = request.POST.get("mac")
        selected_person = request.POST.get("selected_person")
        allegation = request.POST.get("allegation")
        allegation_detail = request.POST.get("allegation-detail")
        print(request.POST)
        # VERIFICATION PROCESS
        try:
            x = PublicKeyRegistery.objects.get(key=pk)
            utils.compare_mac(pk, mac_key)
        except ObjectDoesNotExist:
            return JsonResponse({"error": "Object doesn't exist"})
        except SuspiciousOperation:
            return JsonResponse({"error": "Wrong mac"})

        # ENCRYPT PLAIN TEXT
        key, nonce, ct = utils.generate_cypher_text(allegation_detail)

        # CREATE METADATA
        metadata = f"{selected_person}|{allegation}"
        tag = utils.generate_mac(metadata)

        # TODO: Create a mechanism to store user data

    return render(request, "core/filing.html", {"people": employees})