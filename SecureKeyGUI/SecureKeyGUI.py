'''
Name: SecureKey Password Manager
File Name: SecureKeyGUI.py
Author: Andrew Du
Purpose: SecureKey Password Manager is a Python program designed to help individuals and employees securely store 
and manage their login credentials for websites and various online services. It provides a convenient 
and safe way to keep track of sensitive information, ensuring that your passwords are stored and accessed securely.

Key Features:
- Secure Credential Storage: Your login information, including usernames and passwords, is encrypted and stored securely.
- Master Key: The program implements a master key for decrypting stored data. The master key's hash is saved in a file named master.key, adding an extra layer of security.
- Encrypted Data File: All the stored credentials are encrypted and saved in a file named passwords.txt, protecting your data from unauthorized access.
- Password Generation: SecureKey Password Manager offers a built-in password generator to create strong and unique passwords.
- GUI version with user friendly interface

Start Date: 24 Oct 2023
End Date: 30 Oct 2023

SecureKey Password Manager is a powerful and easy-to-use tool for maintaining the security of your login credentials. 
It helps you organize your passwords and ensures that your data is kept safe from prying eyes.

Get started today and enjoy the peace of mind that comes with knowing your sensitive information is well-protected.

Requirement:
Install the following packages before running the script.

pip install cryptography 
pip install password_generator 
pip install tkinter
pip install datetime
pip install customkinter
'''

from tkinter import messagebox
from customtkinter import *
from PIL import Image
from password_generator import PasswordGenerator
import pyperclip
from cryptography.fernet import Fernet
from hash_encrypt_decrypt import HashEncryptDecrypt
from datetime import datetime
from CTkTable import *
from CTkTableRowSelector import *
import re
from login import Login
from createlogin import CreateNewLogin


# Ouput file name
master_key_file = 'Master.key'
credential_file = 'credentials.dat'

# Securekeypasswordmanager class
class SecureKeyPasswordManager(CTk):
    def __init__(self, master_password):
        super().__init__()
        self.master_password = master_password
        self.geometry("660x400")
        self.title("SecureKey Password Manager")
        self.resizable(0, 0)
        self.iconbitmap('logo2_t.ico')
# Create left Frame widget for user options and right Frame widget for user input
        self.frame_left = CTkFrame(master=self, width=200, height=400)
        self.frame_left.pack_propagate(0)
        self.frame_left.pack(expand=False, side="left",padx = 5)
        self.img_frame_right = CTkFrame(master=self, width=460, height=400)
        self.add_frame_right = CTkFrame(master=self, width=460, height=400)
        self.view_frame_right = CTkFrame(master=self, width=460, height=400)
        self.generate_frame_right = CTkFrame(master=self, width=460, height=400)
        self.delete_frame_right = CTkFrame(master=self, width=460, height=400)
        
        logo_label = CTkLabel(master=self.frame_left, text="Select options:", font=CTkFont(size=20, weight="bold"))
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        menu_add_button = CTkButton(master=self.frame_left, text="Add", command=self.add_credentials)
        menu_add_button.grid(row=1, column=0, padx=20, pady=10)

        menu_view_button = CTkButton(master=self.frame_left, text="View", command=self.view_credentials)
        menu_view_button.grid(row=2, column=0, padx=20, pady=10)

        menu_delete_button = CTkButton(master=self.frame_left, text="Delete", command=self.delete_credentials)
        menu_delete_button.grid(row=3, column=0, padx=20, pady=10)

        menu_generate_button = CTkButton(master=self.frame_left, text="Generate Password", command=self.generate_password)
        menu_generate_button.grid(row=4, column=0, padx=20, pady=10)

        appearance_mode_label = CTkLabel(master=self.frame_left, text="Appearance Mode:", anchor="w")
        appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))

        self.appearance_mode_optionemenu = CTkOptionMenu(master=self.frame_left, values=["System", "Light", "Dark"],
                                                        command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))
        self.load_image()
        #dialog = CTkInputDialog(text="Enter Password:", title="Test")
        #print("Password:", dialog.get_input())
        
# Implement the load_image method
        
    def load_image(self):
        self.img_frame_right.pack_propagate(0)
        self.img_frame_right.pack(expand=True, side="right")

        # Create the image label
        
        # Create the text label
        text_label = CTkLabel(master=self.img_frame_right, text="SecureKey Developed by Andrew Du", 
                                text_color="white",font=('sans-serif', 20),compound = TOP)
        text_label.pack(expand=False, side='bottom')
        # Bring the text label to the foreground
        side_secure_img = Image.open("securekey3.png")
        side_img = CTkImage(dark_image=side_secure_img, light_image=side_secure_img, size=(460, 410))
        image_label = CTkLabel(master=self.img_frame_right,image=side_img,text='')
                                   
        image_label.pack(expand=False, side='top') 
        # Implement the add_credentials method
    def add_credentials(self):
        self.view_frame_right.forget()
        self.generate_frame_right.forget()
        self.img_frame_right.forget()
        self.delete_frame_right.forget()
        self.add_frame_right.pack_propagate(0)
        self.add_frame_right.pack(expand=True, side="right")
        user_name_var = StringVar()
        pass_var = StringVar()
        url_var = StringVar()
        
        title_label = CTkLabel(master=self.add_frame_right, text='Add User Credentials',
                           font = CTkFont(size= 20, weight= 'bold'))
        title_label.pack(padx = 10, pady = (40,20))
        add_frame = CTkFrame(master=self.add_frame_right)
        add_frame.pack(padx = 10, pady = (20, 5), fill = 'both')
        user_label = CTkLabel(add_frame, text="Enter User Name:")
        entry_user = CTkEntry(add_frame, textvariable=user_name_var, width= 220)
        user_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        entry_user.grid(row=0, column=3, padx=10, pady=10)

        pass_label = CTkLabel(add_frame, text="Enter Password:")
        entry_pass = CTkEntry(add_frame, textvariable=pass_var, width= 220, show='*')
        pass_label.grid(row=1, column=2, padx=10, pady=10, sticky="w")
        entry_pass.grid(row=1, column=3, padx=10, pady=10)
        url_label = CTkLabel(add_frame, text="Enter URL:")
        entry_url = CTkEntry(add_frame, textvariable=url_var, width= 220)
        entry_url.grid(row=2, column=3, padx=10, pady=10)
        url_label.grid(row=2, column=2, padx=10, pady=10, sticky="w")
        entry_user.focus_set()
        button_ok = CTkButton(add_frame, text="Save", command=lambda: self.save_event(user_name_var,pass_var,url_var,entry_user,entry_pass,entry_url))
        button_ok.grid(row=3, column=2, padx=10, pady=10)

        button_cancel = CTkButton(add_frame, text="Clear", command=lambda: self.clear_event(entry_user,entry_pass,entry_url))
        button_cancel.grid(row=3, column=3, padx=10, pady=10)
        
         # Implement the clear_event method


            
    def save_event(self, user_name_var, pass_var, url_var, entry_widget, pass_widget, url_widget):
        username = user_name_var.get()
        pass_word = pass_var.get()
        url = url_var.get()
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M")
        credentials = f'User Name: {username}\nPassword: {pass_word}\nURL/resource: {url}\nDate Created: {formatted_datetime}\n\n'
        self.write_file(credentials)
        
        entry_widget.delete(0,END)  #clear the entry box after save
        pass_widget.delete(0,END)
        url_widget.delete(0,END)
        entry_widget.focus_set()
        messagebox.showinfo(username +"'s credentials is saved to database              ")        
        print(username, pass_word,url)     
        
    def write_file(self, credentials):
        hash_en = HashEncryptDecrypt()
        key = hash_en.generate_key(self.master_password)
        fer = Fernet(key.decode())
        
        if os.path.exists(credential_file):    #credential file exists open file decrypt data append data to new data encrypt write to file          
            decrypted_data = self.read_file()
            decrypted_data_new =  decrypted_data.decode()  + credentials     
            encrypted_credentials = fer.encrypt(decrypted_data_new.encode())
            with open(credential_file, 'wb') as f:
                f.write(encrypted_credentials + b'\n')                
        else:
            encrypted_credentials = fer.encrypt(credentials.encode())    
            with open(credential_file, 'wb') as f:
                f.write(encrypted_credentials + b'\n')
                            
                    
# Convert the user credentials into a list
    def convert_to_list(self, credentials):
        # Define regular expressions to extract the information
        user_pattern = r"User Name: (.+)"
        password_pattern = r"Password: (.+)"
        url_pattern = r"URL/resource: (.+)"
        date_pattern = r'Date Created: (.+)'

        # Initialize an empty list to store the data
        data_list = []

        # Split the input string into individual records based on empty lines
        record_strings = credentials.strip().split('\n\n')

        # Append the column headers to the data list
        data_list.append(['User Name', 'Password', 'URL'])

        for record_string in record_strings:
            # Extract the information for each record
            user_match = re.search(user_pattern, record_string)
            password_match = re.search(password_pattern, record_string)
            url_match = re.search(url_pattern, record_string)
           # date_match = re.search(date_pattern, record_string)

            # Create a list for each record and append it to the data list
            record_data = [
                user_match.group(1) if user_match else None,
                password_match.group(1) if password_match else None,
                url_match.group(1) if url_match else None,
                #date_match.group(1) if date_match else None
            ]
            data_list.append(record_data)
           
        return(data_list)
    
    # function to read user credentials from file
    def read_file(self):
        hash_en = HashEncryptDecrypt()
        key = hash_en.generate_key(self.master_password)
        fer = Fernet(key.decode()) 
        
        with open(credential_file, 'rb') as f:
            encrypted_data = f.read()
            if hash_en.verify_fernet_token(encrypted_data,key) == True:
                encrypted_data = encrypted_data.decode()
                decrypted_data = fer.decrypt(encrypted_data)
                
                return decrypted_data
            else:
                messagebox.showwarning('Error: The secret key is incorrect or the data has been tampered            ')
                print('Error: The secret key is incorrect or the data has been tampered \n')
                          
# Implement your code to view credentials here
    def view_credentials(self):
        self.add_frame_right.forget()
        self.generate_frame_right.forget()
        self.img_frame_right.forget()
        self.delete_frame_right.forget()
        data_list = []
        self.view_frame_right.pack_propagate(0)
        self.view_frame_right.pack(expand=True, side="right")
        
        for widget in self.view_frame_right.winfo_children():
            widget.destroy()
            
        title_label = CTkLabel(master=self.view_frame_right, text='View User Credentials',
                           font = CTkFont(size= 20, weight= 'bold'))
        title_label.pack(padx = 10, pady = (40,20))
        view_frame = CTkFrame(master=self.view_frame_right)
        view_frame.pack(padx = 10, pady = (20, 5), fill = 'both')

        #view_tbox = CTkTextbox(master=self.view_frame_right, width=400,height=400, corner_radius=0)
        #view_tbox.grid(row=0, column=0, sticky="w")
        if os.path.exists(credential_file):
            decrypt_data = self.read_file()
            data_list = self.convert_to_list(decrypt_data.decode())
            #print(data_list)
            table = CTkTable(view_frame, row=10, column=3, values=data_list)
            table.pack(expand=True, fill="both", padx=2, pady=2)
            row_selector = CTkTableRowSelector(table)
            print(row_selector.get())
            #table.load_table_data()
        else:
            messagebox.showwarning('Please add records to database first before viewing.           ')
 
            
        
        # Implement the delete_credentials method 

    def clear_event(self, entry_widget, pass_widget, url_widget):
        entry_widget.delete(0,END)
        pass_widget.delete(0,END)
        url_widget.delete(0,END)
        entry_widget.focus_set()
        
        # Implement the save_event method
    
    def delete_credentials(self):
        self.add_frame_right.forget()
        self.view_frame_right.forget()
        self.img_frame_right.forget()
        self.generate_frame_right.forget()
    
        self.delete_frame_right.pack_propagate(0)
        self.delete_frame_right.pack(expand=True, side="right")
        side_delete_img = Image.open("delete.png")
        delete_img = CTkImage(dark_image=side_delete_img, light_image=side_delete_img, size=(460, 410))
        CTkLabel(master=self.delete_frame_right, text="",image=delete_img, text_color="yellow",font=('sans-serif',20)).pack(expand=False, side='top')

        if os.path.exists(credential_file):
                confirm = messagebox.askyesno("Delete Confirmation", "Are you sure you want to delete the file?")
                if confirm:
                        os.remove(credential_file)
                        messagebox.showinfo("File Deleted", "The file has been deleted.")
                else:
                        messagebox.showinfo("Deletion Canceled", "File deletion has been canceled.")
        else:
                messagebox.showwarning('No database', 'The file does not exist.')
        
       

        
       
# Implement the password generater 
    def generate_password(self):
        # Forget other frames and display the generate_frame_right
        self.add_frame_right.forget()
        self.view_frame_right.forget()
        self.img_frame_right.forget()
        self.delete_frame_right.forget()
        self.generate_frame_right.pack_propagate(0)
        self.generate_frame_right.pack(expand=True, side="right")
        title_label = CTkLabel(self.generate_frame_right, text='Password Generator',
                           font = CTkFont(size= 20, weight= 'bold'))
        title_label.pack(padx = 10, pady = (40,20))
        # Create a slider to select the password length
        self.passw_len_frame = CTkFrame(self.generate_frame_right)
        self.passw_len_frame.pack(padx = 10, pady = (20, 5), fill = 'both')
        self.passw_len_label = CTkLabel(self.passw_len_frame, text='Set Password Length',font = CTkFont(weight='bold') )
        self.passw_len_label.pack()
        self.passw_len = CTkSlider(self.passw_len_frame, from_= 1, to=50, number_of_steps=47, width= 400)
        self.passw_len.pack(pady=10, padx = 20)
        self.generate_frame = CTkFrame(self.generate_frame_right)
        self.generate_frame.pack(padx = 10, pady = (20, 5), fill = 'both')
        password_display = CTkEntry(self.generate_frame,width=400)
        password_display.grid(row=20, column=0, padx=5, pady=5,columnspan=3)
        button_generate = CTkButton(self.generate_frame, text="Generate", command=lambda:self.generate_and_display_password(self.passw_len,password_display))
        button_generate.grid(row=30, column=1, padx=10, pady=10)
        button_copy = CTkButton(self.generate_frame, text="Copy", command=lambda:self.copy_password_to_clipboard(password_display))
        button_copy.grid(row=30, column=2, padx=10, pady=10)
        
  
        
       
        
       
# Implement the generate_and_display_password method
    def generate_and_display_password(self, passw_len, password_display):
        pwo = PasswordGenerator()
        password_length = int(passw_len.get()) # Get the selected password length
        password = pwo.non_duplicate_password(password_length)
        password_display.delete(0, "end")  # Clear the existing text in the Entry
        if password_length < 5:
           
            password_display.insert("0", password )
            password_display.configure(text_color= 'red')            
        
            
        elif password_length <9 and password_length >=5:
            password_display.insert("0", password, )
            password_display.configure(text_color= 'yellow')
            
        elif password_length< 13 and password_length >=9: 
            password_display.insert("0", password, )
            password_display.configure(text_color= 'green')  
            
        else:
           password_display.insert("0", password, )  
           password_display.configure(text_color= 'white') 
        
        print(password)
        
        
  # Implement the copy_password_to_clipboard method
    def copy_password_to_clipboard(self, password_display):
        password = password_display.get() # Get the displayed password
        pyperclip.copy(password)
                # Code to copy 'password' to the clipboard
        print(password)
                # Create a "Copy" button that calls copy_password_to_clipboard
    
      
 # Implement the change_appearance_mode_event method
    def change_appearance_mode_event(self, new_appearance_mode: str):
        set_appearance_mode(new_appearance_mode)
        
        # Implement the change_appearance_mode_event method

    def main_menu(self):
        self.mainloop()

# Create an instance of the SecureKeyPasswordManager class and run the application

if __name__ == "__main__":
      
    if os.path.exists(master_key_file):
        login_app = Login()
     
        app = SecureKeyPasswordManager(login_app.master_key)
        app.main_menu()
        
  
    else:
        create_login_app = CreateNewLogin()
        app = SecureKeyPasswordManager(create_login_app.confirm_password)
        app.main_menu()


   
    
        
    
 