'''
Name: HashEncryptDecrypt
File Name: hash_encrypt_decrypt.py
Date started: 25 Oct 2023
Author: Andrew Du
Purpose: 
This script defines a Python class called HashEncrypt that provides functionality for securely managing a master password.
It can hash the password, save the hash to a file, and verify the password by comparing it to the stored hash. 
Additionally, it can generate a cryptographic key and verify Fernet tokens for encryption purposes. 
This script can be used for securing sensitive data and password management.

'''
import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64

class HashEncryptDecrypt:
    def __init__(self):
        pass
     

    
    def get_password_hash(self,password, salt):
        # Create a new hash object
        hasher = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        # Combine the salt and hash, and convert to a hexadecimal representation
        salted_password_hash = salt + hasher

        return salted_password_hash

    
    def save_password_hash_to_file(self, password, file_name):
        salt = os.urandom(16)  # Generate a random salt
        password_hash = self.get_password_hash(password, salt)
        with open(file_name, 'wb') as file:
            file.write(salt + password_hash)

    
    def verify_password(self, input_password, file_name):
        with open(file_name, 'rb') as file:
            data = file.read()
            salt = data[:16]
            stored_password_hash = data[16:]

        # Hash the input password with the same salt
        input_password_hash = self.get_password_hash(input_password, salt)

        # Compare the entire hashes
        if input_password_hash == stored_password_hash:
            return True
        else:
            return False

    
    def generate_key(self, pass_from_user):
        password = pass_from_user.encode()
        mysalt = b'q\xe3Q5\x8c\x19~\x17\xcb\x88\xc6A\xb8j\xb4\x85'

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=mysalt,
            length=32,
            backend=default_backend(),
        )

        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    
    def verify_fernet_token(self, token, secret_key):
        try:
            fernet = Fernet(secret_key)
            fernet.decrypt(token)  # This line will raise an exception if the token is invalid.
            return True
        except InvalidToken:
            return False

    # Additional methods for user credentials can be added here






