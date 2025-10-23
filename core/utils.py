from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

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
        return True
    except InvalidSignature:
        return False