from tkinter import *
from tkinter import messagebox
import random
import rsa
import os
import pyperclip
import base64
import json

GREY = "#313543"
WHITE = "#ffffff"
WEBSITE_PROTOCOL = "https://"

# ---------------------------- ENCRYPTION / DECRYPTION ------------------------------- #

# Check if the public key and private key files exist in the rsa_keys folder
if not os.path.exists("rsa_keys/public.pem") or not os.path.exists("rsa_keys/private.pem"):
    print("The public key file does not exist. Generating a new key...")
    publicKey, privateKey = rsa.newkeys(2048)

    # Store both keys in the rsa_keys folder
    with open("rsa_keys/public.pem", "wb") as public_file:
        public_file.write(publicKey.save_pkcs1())
    with open("rsa_keys/private.pem", "wb") as private_file:
        private_file.write(privateKey.save_pkcs1())

else:
    # Load the public key
    with open("rsa_keys/public.pem", "rb") as public_file:
        publicKey = rsa.PublicKey.load_pkcs1(public_file.read())

    # Load the private key
    with open("rsa_keys/private.pem", "rb") as private_file:
        privateKey = rsa.PrivateKey.load_pkcs1(private_file.read())


def encrypt_password(public_key, password):
    encrypted_password = rsa.encrypt(password.encode(),
                                     public_key)
    return encrypted_password


# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# Reference: https://www.udemy.com/course/100-days-of-code/

def generate_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = []

    password_letters = [random.choice(letters) for _ in range(nr_letters)]
    password_symbols = [random.choice(symbols) for _ in range(nr_symbols)]
    password_numbers = [random.choice(numbers) for _ in range(nr_numbers)]

    password_list = password_letters + password_symbols + password_numbers

    random.shuffle(password_list)

    password = "".join(password_list)

    print(f"Your password is: {password}")

    # Update the password entry box
    entry_password.delete(0, END)
    entry_password.insert(END, string=password)

    # Copy the password to the clipboard
    pyperclip.copy(password)

    return password


# ---------------------------- SAVE PASSWORD ------------------------------- #

def save():
    # Get the user input
    website = entry_website.get()
    username = entry_username.get()
    password = entry_password.get()

    # Check if the website already exists in the passwords_dict
    if website in passwords_dict:
        messagebox.showerror("Error", "This website already exists in the password manager.")
        return

    # Warn the user if any fields are empty
    if website == WEBSITE_PROTOCOL or username == "" or password == "":
        messagebox.showerror("Error", "Please fill in all fields.")

    else:
        # Show a popup message box of user input
        is_ok = messagebox.askokcancel(title=website,
                                       message=f"Website: {website}\nUsername: {username}\nPassword: {password}\n"
                                               f"Is it okay to save?")

        if is_ok:

            # Encrypt the password
            encrypted_password = encrypt_password(publicKey, password)

            # Convert the password from bytes to string
            encrypted_password_string = base64.b64encode(encrypted_password).decode("utf-8")

            # Create a dictionary of new data
            new_data = {
                website: {
                    "username": username,
                    "password": encrypted_password_string
                }
            }

            try:
                with open("passwords.json", "r") as json_file:
                    existing_data = json.load(json_file)  # Load the existing data
                    existing_data.update(new_data)  # Update the existing data with the new data
            except FileNotFoundError:
                existing_data = new_data

            with open("passwords.json", "w") as json_file:
                json.dump(existing_data, json_file, indent=4)  # Save the updated data to the JSON file

            print(f"Saved {website} to the password manager.")
            print(f"Website: {website}\nUsername: {username}\nEncrypted Password: {encrypted_password}")

            # Empty the entry boxes
            entry_website.delete(0, END)
            entry_website.insert(END, string=WEBSITE_PROTOCOL)
            entry_username.delete(0, END)
            entry_password.delete(0, END)


# ---------------------------- LOAD PASSWORD ------------------------------- #


# Load passwords from the JSON file into a dictionary
def load_passwords():
    # Only load if the file exists
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as json_file:
            passwords = json.load(json_file)
            return passwords
    else:
        return {}


def load_website_password():
    # Get the website from the entry box
    website = entry_website.get()

    # Check if the website exists in the passwords_dict
    if website in passwords_dict:
        # Get the username and password from the passwords_dict
        username = passwords_dict[website]['username']
        password = passwords_dict[website]['password']

        print(f"Website: {website}\nUsername: {username}\nEncrypted Password: {password}")

        # Convert the password from string to bytes
        password_bytes = base64.b64decode(password)

        # Decrypt the password
        decrypted_password = rsa.decrypt(password_bytes, privateKey)
        decrypted_password = decrypted_password.decode()

        # Update the password entry box
        entry_password.delete(0, END)
        entry_password.insert(END, string=decrypted_password)

        # Update the username entry box
        entry_username.delete(0, END)
        entry_username.insert(END, string=username)

        # Copy the password to the clipboard
        pyperclip.copy(decrypted_password)

    else:
        messagebox.showerror("Error", "This website does not exist in the password manager.")


# ---------------------------- UI SETUP ------------------------------- #

# Load saved passwords
passwords_dict = load_passwords()

# Creating a new window and configurations
window = Tk()
window.title("Password Manager")
window.minsize(width=500, height=300)

# Add some padding (spaces around all widgets)
window.config(padx=20, pady=20, bg=GREY)

# Create a canvas
canvas = Canvas(width=250, height=200, highlightthickness=0, bg=GREY)
# Add image at the center
logo_img = PhotoImage(file="icons8-lock-200.png")
canvas.create_image(100, 100, image=logo_img)
canvas.grid(column=1, row=1, rowspan=3)

# Labels
label_website = Label(text="Website", bg=GREY, fg=WHITE)
label_website.grid(column=2, row=1)

label_username = Label(text="Username", bg=GREY, fg=WHITE)
label_username.grid(column=2, row=2)

label_password = Label(text="Password", bg=GREY, fg=WHITE)
label_password.grid(column=2, row=3)

# Entries
entry_website = Entry(width=20)
entry_website.focus()
entry_website.insert(END, string=WEBSITE_PROTOCOL)
entry_website.grid(column=3, row=1)

entry_username = Entry(width=35)
entry_username.insert(END, string="")
entry_username.grid(column=3, row=2, columnspan=2)

entry_password = Entry(width=20)
entry_password.insert(END, string="")
entry_password.grid(column=3, row=3)

# calls action() when pressed
button_load_password = Button(text="Load Pwd", command=load_website_password)
button_load_password.grid(column=4, row=1)

button_generate_password = Button(text="Generate", command=generate_password)
button_generate_password.grid(column=4, row=3)

button_add = Button(text="Save", command=save, width=32)
button_add.grid(column=3, row=4, columnspan=2)

# Keep the window open
window.mainloop()
