from django.db import models
from django.utils import timezone
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class CA(models.Model):
    name = models.CharField(max_length=200, null=False, blank=False)
    rsa_private_key = models.TextField(blank=True, null=True)
    rsa_public_key = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Certification Authority"
        verbose_name_plural = "Certification Authorities"

class Personnel(models.Model):
    ca = models.ForeignKey(CA, on_delete=models.CASCADE, related_name='personnel')
    full_name = models.CharField(max_length=200)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    employee_id = models.CharField(max_length=100, blank=True, null=True)
    position = models.CharField(max_length=250, blank=False, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.full_name

    class Meta:
        verbose_name = "Personnel"
        verbose_name_plural = "Personnel"

class Certificate(models.Model):
    ca = models.ForeignKey(CA, on_delete=models.CASCADE, related_name='certificate')
    personnel = models.ForeignKey(Personnel, on_delete=models.CASCADE, related_name='certificate')
    signature = models.TextField(blank=True, null=True)
    issued_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.personnel.full_name

class UserRegistration(models.Model):
    personnel = models.ForeignKey(Personnel, on_delete=models.CASCADE)
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE)
    registered_at = models.DateTimeField(default=timezone.now)
    public_key = models.TextField(blank=True, null=True)

class PublicKeyRegistery(models.Model):
    key = models.TextField(blank=False, null=True)

    class Meta:
        verbose_name = "Public Key Registery"
        verbose_name_plural = "Public Key Registery"

# class Allegation(models.Model):
#     thresho

class PublicAllegation(models.Model):
    alleged = models.ForeignKey(Personnel, on_delete=models.CASCADE, related_name="alleged")
    allegation = models.CharField(max_length=250, null=True, blank=False)

class AllegationItem(models.Model):
    allegation = models.ForeignKey(PublicAllegation, on_delete=models.CASCADE)
    alleger = models.ForeignKey(Personnel, on_delete=models.CASCADE, related_name="alleger")

# TODO 1: Implement Escrow storage and Public share of secret
# TODO 2: Implement Allegations