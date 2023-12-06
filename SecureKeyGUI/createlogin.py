'''
Name: CreateNewLogin
File Name: createlogin.py
Date started: 25 Oct 2023
Author: Andrew Du
Purpose: 
This script creates new login and saved the master password into Master.key 
using HashEncryptDecrpt class to hashed the master password

'''


import os
from tkinter import messagebox
from customtkinter import *
from hash_encrypt_decrypt import HashEncryptDecrypt

# Output file names
master_key_file = 'Master.key'

class CreateNewLogin:
    def __init__(self):
        password_window = CTk()
        self.password_window = password_window
        password_window.title("Create New Password")
        password_window.geometry('300x150')
        self.password_window.iconbitmap('logo2_t.ico')
        self.password_var = StringVar()
        self.confirm_password_var = StringVar()
        self.password_window = password_window
        label1 = CTkLabel(password_window, text="New Password:")
        self.new_password_entry = CTkEntry(password_window, textvariable=self.password_var, show="*")
        label1.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.new_password_entry.grid(row=0, column=1, padx=10, pady=10)

        label2 = CTkLabel(password_window, text="Confirm Password:")
        self.confirm_password_entry = CTkEntry(password_window, textvariable=self.confirm_password_var, show="*")
        label2.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.confirm_password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        submit_button = CTkButton(password_window, text="Create Password", command= self.create_password)
        submit_button.grid(row=2, column=1, padx=10, pady=10)
        self.new_password_entry.focus_set()
        password_window.mainloop()
       
    def create_password(self):
        self.new_password = self.password_var.get()
        self.confirm_password  = self.confirm_password_var.get()
        if self.new_password == self.confirm_password:
            # Store the new password securely, e.g., by encrypting and saving to a "master.key" file
            hash_en = HashEncryptDecrypt()
            hash_en.save_password_hash_to_file(self.confirm_password, master_key_file)
            print(self.confirm_password)
            self.close()
            
        else:
            messagebox.showerror("Error Passwords do not match.")
            messagebox.showinfo("Please try again.")
            self.confirm_password_entry.delete(0, END)
            self.new_password_entry.delete(0, END)
    
    def close(self):
       self.password_window.destroy()
'''
if not os.path.exists(master_key_file):
    # If the "master.key" file does not exist, create a new password
    create_login_app = CreateNewLogin()
    create_login_app.close
    
'''
