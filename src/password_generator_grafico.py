#!/usr/bin/env python3

import random
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.simpledialog import askstring
import nltk
from nltk.corpus import words
from contextlib import redirect_stdout, redirect_stderr
import os
from datetime import datetime
from cryptography.fernet import Fernet
import uuid
import base64
from PIL import Image, ImageTk
from ttkthemes import ThemedStyle

KEY_DIR = os.path.join(os.path.expanduser("~"), ".config", "password_manager_keys")
random_dir_name = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode('utf-8').rstrip('=')
PASSWORD_DIR = os.path.join(os.path.expanduser("~"), ".config", f"pm_{random_dir_name}")
KEY_FILE_PATH = os.path.join(KEY_DIR, "secret.key")
PASSWORD_FILE_PATH = os.path.join(PASSWORD_DIR, "passwords.txt")

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)
if not os.path.exists(PASSWORD_DIR):
    os.makedirs(PASSWORD_DIR)

def generate_key():
    return Fernet.generate_key()

def load_key():
    if os.path.exists(KEY_FILE_PATH):
        with open(KEY_FILE_PATH, "rb") as key_file:
            return key_file.read()
    else:
        key = generate_key()
        with open(KEY_FILE_PATH, "wb") as key_file:
            key_file.write(key)
        return key

key = load_key()
cipher_suite = Fernet(key)

def silent_download():
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull), redirect_stderr(fnull):
            nltk.download('words')

silent_download()

lista_palabras = words.words()
current_password = ""

def generate_password(length, include_symbols, memorizable):
    if memorizable:
        return generate_memorizable_password()
    
    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += string.punctuation
    
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def generate_memorizable_password(num_palabras=3):
    contrasena = '-'.join(random.choice(lista_palabras).capitalize() for _ in range(num_palabras))
    contrasena += str(random.randint(10, 99))
    return contrasena

def on_generate():
    global current_password
    try:
        length = int(entry_length.get())
        include_symbols = var_symbols.get()
        memorizable = var_memorizable.get()
        
        current_password = generate_password(length, include_symbols, memorizable)
        
        text_password.config(state=tk.NORMAL)
        text_password.delete(1.0, tk.END)
        text_password.insert(tk.END, current_password)
        text_password.config(state=tk.DISABLED)
        
        button_save.grid(row=8, column=0, padx=10, pady=10, sticky=tk.EW)
        button_new.grid(row=8, column=1, padx=10, pady=10, sticky=tk.EW)
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for length.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode())

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()

def on_save():
    app_name = entry_app_name.get().strip()
    user_email = entry_user_email.get().strip()
    
    if not app_name:
        messagebox.showwarning("Input Error", "Please enter an application name.")
        return

    if not user_email:
        messagebox.showwarning("Input Error", "Please enter a user or email.")
        return

    if not current_password:
        messagebox.showwarning("No Password", "No password generated to save.")
        return

    try:
        with open(PASSWORD_FILE_PATH, 'a') as file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            encrypted_password = encrypt_message(current_password)
            file.write(f"{timestamp} - {app_name} ({user_email}): {encrypted_password.decode()}\n")
        messagebox.showinfo("Saved", f"Password saved to {PASSWORD_FILE_PATH}")
    except IOError as e:
        messagebox.showerror("Error", f"Could not save password: {e}")

def on_new():
    global current_password
    current_password = ""
    text_password.config(state=tk.NORMAL)
    text_password.delete(1.0, tk.END)
    text_password.config(state=tk.DISABLED)
    button_save.grid_forget()
    button_new.grid_forget()

def copy_to_clipboard():
    password = text_password.get(1.0, tk.END).strip()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard!")

def view_passwords():
    if not os.path.exists(PASSWORD_FILE_PATH):
        messagebox.showinfo("No Passwords", "No passwords have been saved yet.")
        return
    
    try:
        with open(PASSWORD_FILE_PATH, 'r') as file:
            lines = file.readlines()
        
        decrypted_lines = []
        for line in lines:
            try:
                timestamp, rest = line.split(' - ', 1)
                app_info, encrypted_password = rest.split(': ', 1)
                decrypted_password = decrypt_message(encrypted_password.strip().encode())
                decrypted_lines.append(f"{timestamp} - {app_info}: {decrypted_password}")
            except Exception as e:
                decrypted_lines.append(line.strip())

        view_window = tk.Toplevel(root)
        view_window.title("View Passwords")
        view_window.geometry("600x400")
        view_window.configure(bg='#2C2C2C')

        frame = ttk.Frame(view_window)
        frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        text_view = tk.Text(frame, wrap=tk.WORD, height=20, width=80, bg='#1E1E1E', fg='#FFFFFF')
        text_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_view.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_view.config(yscrollcommand=scrollbar.set)

        for line in decrypted_lines:
            text_view.insert(tk.END, line + '\n')

        text_view.config(state=tk.DISABLED)
    except IOError as e:
        messagebox.showerror("Error", f"Could not read passwords: {e}")

def on_delete():
    if os.path.exists(PASSWORD_FILE_PATH):
        confirm = messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete all saved passwords?")
        if confirm:
            try:
                os.remove(PASSWORD_FILE_PATH)
                messagebox.showinfo("Deleted", "All passwords have been deleted.")
                on_new()
                button_new.grid(row=8, column=1, padx=10, pady=10, sticky=tk.EW)
            except IOError as e:
                messagebox.showerror("Error", f"Could not delete passwords: {e}")
    else:
        messagebox.showinfo("No Passwords", "No passwords have been saved yet.")

root = tk.Tk()
root.title("Password Generator")
window_width = 600
window_height = 550
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
root.geometry(f"{window_width}x{window_height}+{x}+{y}")
root.resizable(False, False)

style = ThemedStyle(root)
style.set_theme("arc")  


try:
    logo = Image.open("logo.png")
    logo = logo.resize((100, 100), Image.ANTIALIAS)
    logo_photo = ImageTk.PhotoImage(logo)
    logo_label = tk.Label(root, image=logo_photo, bg='#1E1E1E')
    logo_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
except FileNotFoundError:
    print("El archivo logo.png no se encuentra en la ruta especificada.")

title_label = ttk.Label(root, text="Password Generator", font=('Helvetica', 18, 'bold'))
title_label.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

frame_inputs = ttk.Frame(root, padding="10")
frame_inputs.grid(row=2, column=0, columnspan=2, sticky=tk.W+tk.E, padx=10, pady=10)

ttk.Label(frame_inputs, text="Application Name:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
entry_app_name = ttk.Entry(frame_inputs)
entry_app_name.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)

ttk.Label(frame_inputs, text="User/Email:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
entry_user_email = ttk.Entry(frame_inputs)
entry_user_email.grid(row=1, column=1, padx=10, pady=5, sticky=tk.EW)

ttk.Label(frame_inputs, text="Length of Password:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
entry_length = ttk.Entry(frame_inputs)
entry_length.grid(row=2, column=1, padx=10, pady=5, sticky=tk.EW)

var_symbols = tk.BooleanVar()
ttk.Checkbutton(frame_inputs, text="Include Symbols", variable=var_symbols, onvalue=True, offvalue=False).grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

var_memorizable = tk.BooleanVar()
ttk.Checkbutton(frame_inputs, text="Memorizable", variable=var_memorizable, onvalue=False, offvalue=True).grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

text_password = tk.Text(root, height=2, width=50, bg='#333333', fg='#FFFFFF')
text_password.grid(row=7, column=0, columnspan=2, padx=10, pady=10)
text_password.config(state=tk.DISABLED)

button_save = ttk.Button(root, text="Save Password", command=on_save)
button_new = ttk.Button(root, text="Generate New", command=on_generate)
button_copy = ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
button_delete = ttk.Button(root, text="Delete All Passwords", command=on_delete)
button_view = ttk.Button(root, text="View Passwords", command=view_passwords)

button_save.grid(row=8, column=0, padx=10, pady=10, sticky=tk.EW)
button_new.grid(row=8, column=1, padx=10, pady=10, sticky=tk.EW)
button_copy.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky=tk.EW)
button_delete.grid(row=10, column=0, columnspan=2, padx=10, pady=10, sticky=tk.EW)
button_view.grid(row=11, column=0, columnspan=2, padx=10, pady=10, sticky=tk.EW)

root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.mainloop()