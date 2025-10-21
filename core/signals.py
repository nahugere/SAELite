from django.db.models.signals import post_save, post_delete
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.dispatch import receiver
from .models import *
from . import utils
import secrets


@receiver(post_save, sender=CA)
def create_rsa_keys(sender, instance, created, **kwargs):
    if created and not instance.rsa_private_key:
        s, p = utils.generate_rsa_keys()
        instance.rsa_private_key = s
        instance.rsa_public_key = p
        instance.save()

@receiver(post_save, sender=Certificate)
def sign_certificate(sender, instance, created, **kwargs):
    if created:
        message = secrets.token_urlsafe(20).encode()
        instance.signature = utils.sign(instance.rsa_private_key, message)
        instance.certificate = message
        instance.save()