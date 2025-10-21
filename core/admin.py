from django.contrib import admin
from .models import *

@admin.register(CA)
class CAAdmin(admin.ModelAdmin):
    exclude = ('rsa_private_key', 'rsa_public_key',)

admin.site.register(Personnel)