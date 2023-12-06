'''
Name: SecureKey Password Manager
File Name: SecureKeyCLI.py
Purpose: SecureKey Password Manager is a Python program designed to help individuals and employees securely store 
and manage their login credentials for websites and various online services. It provides a convenient 
and safe way to keep track of sensitive information, ensuring that your passwords are stored and accessed securely.

Key Features:
- Secure Credential Storage: Your login information, including usernames and passwords, is encrypted and stored securely.
- Master Key: The program implements a master key for decrypting stored data. The master key's hash is saved in a file named master.key, adding an extra layer of security.
- Encrypted Data File: All the stored credentials are encrypted and saved in a file named passwords.txt, protecting your data from unauthorized access.
- Password Generation: SecureKey Password Manager offers a built-in password generator to create strong and unique passwords.
- User-Friendly Menu: The program provides an easy-to-use menu for adding, viewing, and managing stored credentials.

Start Date: 10 Oct 2023
End Date: 24 Oct 2023

SecureKey Password Manager is a powerful and easy-to-use tool for maintaining the security of your login credentials. 
It helps you organize your passwords and ensures that your data is kept safe from prying eyes.

Get started today and enjoy the peace of mind that comes with knowing your sensitive information is well-protected.

Requirement:
Install the following packages before running the script.

pip install cryptography 
pip install password_generator 
pip install pyfiglet

'''
import os
import hashlib
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from password_generator import PasswordGenerator
from cryptography.fernet import Fernet, InvalidToken
import pyfiglet
# Ouput file name
master_key_file = 'Master.key'
passwords_file = 'passwords.txt'
# Function to clear the screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    

# Funtction to generate an encryption key
def generate_key(pass_from_user):
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
#This function will raise an InvalidToken exception if the token is invalid, and it will print whether the token is valid or not. 
#If the secret key is incorrect or the data has been tampered with, the token will be considered invalid.
def verify_fernet_token(token, secret_key):
    try:
        fernet = Fernet(secret_key)
        fernet.decrypt(token)  # This line will raise an exception if the token is invalid.
        #print("Token is valid.")
        return True
    except InvalidToken:
        #print("Token is invalid.")
        return False
# Function to add user credentials to the password database
def add(m_password):
    print('Add user credentials and URL/resource encrypt data store into database\n')
    name = input('User Name -> ')
    pwd = input('Password -> ')
    url_resource = input('URL/resource -> ')
    key = generate_key(m_password)
    fer = Fernet(key.decode())
    credentials = f'User Name: {name}\nPassword: {pwd}\nURL/resource: {url_resource}\n'
    if os.path.exists(passwords_file):
        with open(passwords_file, 'rb') as f:
            encrypted_data = f.read()
            if verify_fernet_token(encrypted_data,key) == True:
                encrypted_data = encrypted_data.decode()
                decrypted_data = fer.decrypt(encrypted_data)
                decrypted_data_new =  decrypted_data.decode()  + credentials     
                encrypted_credentials = fer.encrypt(decrypted_data_new.encode())
                with open(passwords_file, 'wb') as f:
                    f.write(encrypted_credentials + b'\n')
                    print('The following credentials have been added to the database and data is encrypted')
                    print(credentials)
            else:
                print('Error: The secret key is incorrect or the data has been tampered \n')
    
        
    else:
        encrypted_credentials = fer.encrypt(credentials.encode())    
        with open(passwords_file, 'wb') as f:
            f.write(encrypted_credentials + b'\n')
            print('The following credentials have been added to the database and data is encrypted')
            print(credentials)
            
# Function to view stored user credentials
def view(m_password):
    key = generate_key(m_password)
    fer = Fernet(key.decode())
    try:
        with open(passwords_file, 'rb') as f:
            print('Viewing stored decrypted credentials from the database\n')
            
        
            encrypted_data = f.read()
            if verify_fernet_token(encrypted_data,key) == True:
                encrypted_data = encrypted_data.decode()
                decrypted_data = fer.decrypt(encrypted_data)
                print(decrypted_data.decode())
            else:
                print('Error: The secret key is incorrect or the data has been tampered \n')
                
    except FileNotFoundError:
        print('Please add records to database first before viewing.\n')
# Function to delete database
def delete():
    print('Delete user credentials and URL/resource database\n')
    try:
        master_key = input('Enter Master password to confirm delete database-> ')
    
        if verify_password(master_key, master_key_file) is True:
            
            os.remove(passwords_file)
            print(f"{passwords_file} has been deleted.\n")
        else:    
            print('Access denied. Incorrect password provided.')
        #user_menu(master_key)
        
    except OSError as e:
        print(f"Error: {e}\n")
   

# Function for generating random passwords
def passw_generator():
    print('Password Generator')
    pwo = PasswordGenerator()  
    answer = ['YES', 'Yes','yes','Y','y']
    user_answer = 'Y'
    #pwo_len = input('Enter password length: ')
    while user_answer in answer:
        pwo_len = input('Enter password length between 3 to 40 chars -> ')
        try:
            pwo_int = int(pwo_len)
            if pwo_int>= 3 and pwo_int <= 40:
                print(pwo.non_duplicate_password(pwo_int))
            else:
                print('Invalid length please enter between 3 to 40 chars')
        except ValueError:
            print("Error: The input is not a valid integer.")
    
        user_answer = input('Do you want to generator another password Y for Yes -> ')   


    
# Function to create hash using the password
def get_password_hash(password, salt):
    # Create a new hash object
    hasher = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    
    # Combine the salt and hash, and convert to a hexadecimal representation
    salted_password_hash = salt + hasher

    return salted_password_hash

# Function to save hashed password to file
def save_password_hash_to_file(password, file_name):
    salt = os.urandom(16)  # Generate a random salt
    password_hash = get_password_hash(password, salt)
    with open(file_name, 'wb') as file:
        file.write(salt + password_hash)

# Function to verify a password against a stored hash
def verify_password(input_password, file_name):
    with open(file_name, 'rb') as file:
        data = file.read()
        salt = data[:16]
        stored_password_hash = data[16:]

    # Hash the input password with the same salt
    input_password_hash = get_password_hash(input_password, salt)

    # Compare the entire hashes
    if input_password_hash == stored_password_hash:
        #print("Password is correct.")
        return True
    else:
        #print("Password is incorrect.")
        return False


# Function Options menu for the user
def user_menu(master_key):
    
    while True:
        print('\nPlease select from the following menu options:')
        option = input('Press A to Add credentials and related URL\nPress V to View stored credentials\nPress D to Delete stored credentials\nPress G to Generate Password\nPress C to clear the screen\nPress X to Exit\n-> ').lower()
        if option == 'x':
            break
        if option == 'a':
            add(master_key)
        elif option == 'v':
            view(master_key)
        elif option == 'd':
            delete()
        elif option == 'g':
            passw_generator()
        elif option == 'c':
            clear_screen()
        else:
            print('Invalid option please select from A,V,D,G,C,X options')
            continue
    print(pyfiglet.figlet_format("Thank you for using SecureKey.", font="Digital"))
    print(pyfiglet.figlet_format("           Have a great day!", font="Digital"))

# Main part of the program

# If the Master.key file exists, ask for the master password and grant access if correct
if os.path.exists(master_key_file):
    #print('***** Welcome to SecureKey Password Manager *****')
    #print('**************Developed by Andrew Du*************\n')
    print(pyfiglet.figlet_format("SecureKey", font="Small"))
    print(pyfiglet.figlet_format("Developed by Andrew Du", font="Digital"))
    master_key = input('Enter Master password -> ')
    
    while verify_password(master_key, master_key_file) is False:
        print('Access denied. Incorrect password provided.')
        master_key = input('Enter Master password -> ')
            
    print('Access granted.\n')
    user_menu(master_key)
    
# If the Master.key file does not exist, set the master password and save it        
else:
    print(pyfiglet.figlet_format("SecureKey", font="Small"))
    print(pyfiglet.figlet_format("Developed by Andrew Du", font="Digital"))
    password = input("Set new password -> ")
    confirm_password = input('Confirm password -> ')
    while password != confirm_password:
        print('Confirm password does not match. Try again.')
        confirm_password = input('Confirm password -> ')

    save_password_hash_to_file(password, master_key_file)
    print('Password hash has been saved to Master.key.')
    user_menu(password)
    
