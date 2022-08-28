import base64
from select import select
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import json

import sys
import random
import getpass
import os

#fernet cipher
def encrypt(password, text):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'\x88G\x9f\xb3l\x82T\x15\xddtP\xd7\xec\x06\x9f\xbe',
    iterations=390000,
    )
    f = Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))
    return f.encrypt(text.encode()).decode()
def decrypt(password, text):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'\x88G\x9f\xb3l\x82T\x15\xddtP\xd7\xec\x06\x9f\xbe',
    iterations=390000,
    )
    f = Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))
    return f.decrypt(text.encode()).decode()

def list_accounts(data):
    list_names_account = []
    number_print = 1
    for i in data["accounts"]:
        print(f"{number_print}){i}")
        number_print += 1
        list_names_account.append(i)
    return(list_names_account)

#actions
def create(data, password):
    name_account = input("name for account: ")
    data["accounts"][name_account] = {
        "user":encrypt(password, input("username: ")),
        "password":None
    }
    select_random_or_not = ""
    while select_random_or_not != "yes" and select_random_or_not != "no":
        select_random_or_not = input("password random yes/no: ")
    if select_random_or_not == "yes":
        legth_password = None
        while legth_password == None:
            try:
                legth_password = int(input("password legth: "))
            except:
                pass
        characters = "qwertyuiopasdfghjklzxcvbnm1234567890,.;:^*¨Ç[]{}\~?¿'¡!$%&/()=#@<>-_"
        passwd = ""
        for i in range(0, legth_password):
            passwd = passwd + characters[random.randint(0, len(characters)-1)]
        print(password, passwd)
        data["accounts"][name_account]["password"] = encrypt(password, passwd)
    else:
        data["accounts"][name_account]["password"] = encrypt(password, input("password: "))
    os.system("clear")
    return data
def view(data, password, name):
    print("---"+name+"---")
    print("username: " + decrypt(password, data["accounts"][name]["user"]))
    print("password: " + decrypt(password, data["accounts"][name]["password"]))