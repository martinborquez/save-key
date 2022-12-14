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

def create_hash(text):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(text.encode())
    return str(digest.finalize())

#get and save data
def save_data(path, dictionary):
    with open(path, "w") as objfile:
        json.dump(dictionary, objfile)
def read_data(path):
    with open(path, "r") as objfile:
        return json.load(objfile)

def list_accounts(data):
    list_names_account = []
    number_print = 1
    for i in data["accounts"]:
        print(f"{number_print}){i}")
        number_print += 1
        list_names_account.append(i)
    return(list_names_account)

def verify_file(data, password, path):
    if "data_name" in data and "accounts" in data:

        if data["data_name"] == create_hash(password):
            return True
        else:
            return False
    else:
        passwd_1 = "pass_1"
        passwd_2 = "pass_2"
        os.system("clear")
        print("Create New password to use")
        while passwd_1 != passwd_2:
            passwd_1 = getpass.getpass("New Password: ")
            passwd_2 = getpass.getpass("Repeat Password: ")
        save_data(path, {"data_name":create_hash(passwd_1),"accounts":{}})
        return True
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
        characters = "qwertyuiopasdfghjklzxcvbnm1234567890,.;:^*????[]{}\~???'??!$%&/()=#@<>-_"
        passwd = ""
        for i in range(0, legth_password):
            passwd = passwd + characters[random.randint(0, len(characters)-1)]
        data["accounts"][name_account]["password"] = encrypt(password, passwd)
    else:
        data["accounts"][name_account]["password"] = encrypt(password, input("password: "))
    os.system("clear")
    return data
def view(data, password, name):
    print("---"+name+"---")
    print("username: " + decrypt(password, data["accounts"][name]["user"]))
    print("password: " + decrypt(password, data["accounts"][name]["password"]))
    input("Next: ")
    os.system("clear")
def modify(data, password, name):
    modify_option = input("1)user\n2)password\n")
    if modify_option == "1":
        data["accounts"][name]["user"] = encrypt(password, input("username: "))
        return data
    elif modify_option == "2":
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
            characters = "qwertyuiopasdfghjklzxcvbnm1234567890,.;:^*????[]{}\~???'??!$%&/()=#@<>-_"
            passwd = ""
            for i in range(0, legth_password):
                passwd = passwd + characters[random.randint(0, len(characters)-1)]
            data["accounts"][name]["password"] = encrypt(password, passwd)
        else:
            data["accounts"][name]["password"] = encrypt(password, input("password: "))
        os.system("clear")
        return data
    else:
        return modify(data, password, name)
def remove(data, name):
    print("remove "+name)
    remove_option = input("yes/no: ")
    if remove_option == "yes":
        data["accounts"].pop(name)
        return data
    

if __name__ == '__main__':
    data = read_data(sys.argv[1])
    password = getpass.getpass("Password: ")
    while verify_file(data, password, sys.argv[1]) != True:
        password = getpass.getpass("Password: ")
    data = read_data(sys.argv[1])
    run_app = True
    while run_app == True:
        os.system("clear")
        print("__Menu__")
        print("options:\n1)Create new account\n2)change account values\n3)view account values\n4)remove account")
        election = input("election: ")
        if election == "1":
            create(data, password)
        elif election == "2":
            accounts = list_accounts(data)
            try:
                modify(data, password, accounts[int(input("selection: "))-1])
            except:
                print("invalid option")
        elif election == "3":
            accounts = list_accounts(data)
            try:
                view(data, password, accounts[int(input("selection: "))-1])
            except:
                print("invalid option")
        elif election == "4":
            accounts = list_accounts(data)
            try:
                remove(data, accounts[int(input("selection: "))-1])
            except:
                print("invalid option")
        save_data(sys.argv[1], data)