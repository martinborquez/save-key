import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import json

import sys
import random
import getpass

#fernet cipher
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'\x88G\x9f\xb3l\x82T\x15\xddtP\xd7\xec\x06\x9f\xbe',
    iterations=390000,
)
def encrypt(password, text):
    f = Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))
    return f.encrypt(text.encode()).decode()
def decrypt(password, text):
    f = Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))
    return f.decrypt(text.encode()).decode()