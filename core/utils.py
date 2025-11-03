import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from django.core.exceptions import SuspiciousOperation
from cryptography.exceptions import InvalidSignature
from decouple import config
from .models import *
import hashlib
import base64
import hmac

def generate_rsa_keys():
    k = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    sk = k.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    pk = k.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return sk, pk

def sign(private_keys, message):
    sk = serialization.load_pem_private_key(
        private_keys.encode(),
        password=None,
        backend=default_backend()
    )
    signature = sk.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def generate_mac(pk):
    secret = config("SECRETKEY").encode("utf-8")
    hmac_object = hmac.new(secret, pk.encode("utf-8"), hashlib.sha256)
    return hmac_object.hexdigest()

def generate_cypher_text(data):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)
    return key, nonce, ct

def decrypt_cypher_text(key, nonce, ct):
    aesgcm = AESGCM(key)
    dt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return dt

def compare_mac(pk, mac):
    p = generate_mac(pk)
    if hmac.compare_digest(p, mac):
        return True
    else:
        raise SuspiciousOperation

def create_key_pairings(n):
    keys = []
    for i in range(n):
        k = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        sk = k.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        pk = k.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        hmac_o = generate_mac(pk)
        keys.append((pk, sk, hmac_o))
        x = PublicKeyRegistery(key=pk)
        x.save()
    return keys


def verify_cert(public_key, message, signature):
    signature_b = base64.b64decode(signature)
    pk = serialization.load_pem_public_key(
        public_key.encode(),
        backend=default_backend()
    )
    d = message.encode()
    try:
        pk.verify(
            signature_b,
            d,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, create_key_pairings(3)
    except InvalidSignature:
        return False, []