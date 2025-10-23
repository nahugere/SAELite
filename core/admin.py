from django.contrib import admin, messages
from .models import *

@admin.register(CA)
class CAAdmin(admin.ModelAdmin):
    exclude = ('rsa_private_key', 'rsa_public_key',)

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    exclude = ('signature',)

admin.site.register(Personnel)