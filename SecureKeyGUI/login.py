'''
Name: Login 
File Name: login.py
Date started: 25 Oct 2023
Author: Andrew Du
Purpose: 
This script check the master password with Master.key
using HashEncryptDecrpt class to verify if the correct Master password is entered

'''

import os
from tkinter import messagebox
from customtkinter import *
from hash_encrypt_decrypt import HashEncryptDecrypt

# Output file names
master_key_file = 'Master.key'

class Login:
    def __init__(self):
        #super().__init__()
        
        root = CTk()
        root.title("Password Entry")
        root.geometry('300x150')
        self.root = root
        self.root.iconbitmap('logo2_t.ico')
        label = CTkLabel(root, text="Enter Password:")
        label.pack(pady=10)
        self.password_var = StringVar()
        self.password_entry = CTkEntry(root, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=10)

        submit_button = CTkButton(root, text="Submit", command=self.check_password)
        submit_button.pack()
        
        root.mainloop()


    def check_password(self):
        self.master_key = self.password_var.get()
        hash_en = HashEncryptDecrypt()
        
        if hash_en.verify_password(self.master_key, master_key_file):
            print('Access granted.\n')
            print(self.master_key)
            self.close()
            
          
        else:
            messagebox.showerror("Incorrect password")
            messagebox.showinfo('Access denied, try again')
            self.password_entry.delete(0, END)
            self.password_entry.focus_set()
   
    def close(self):
       self.root.destroy()                

'''     
if os.path.exists(master_key_file):
    # If the "master.key" file exists, use the password entry GUI
    login_app = Login()
    #if login_app.check_password():
    login_app.close()
'''