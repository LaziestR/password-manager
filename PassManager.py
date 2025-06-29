#Group 7, Password Manager

import os
import json
import bcrypt
import getpass
import base64
from cryptography.fernet import Fernet

VAULT_DIR = "vault"

def ensure_vault_dir():
     if not os.path.exists(VAULT_DIR):
          os.makedirs(VAULT_DIR) # Corrected from os.markedirs

def get_vault_path(username):
     return os.path.join(VAULT_DIR, f"{username}.json")

def load_vault(username):
     path = get_vault_path(username)
     if not os.path.exists(path):
          return []
     with open(path, "r") as f:
          return json.load(f)
     
def save_vault(username, entries):
     path = get_vault_path(username)
     with open(path, "w") as f:
          json.dump(entries, f, indent=4)

#vault's actions

def add_vault_entry(username, vault_key): # Added vault_key parameter
     service = input("Service name: ")
     uname = input("Username: ")
     pwd = getpass.getpass("Password: ")

     f = Fernet(vault_key.encode())
     encrypted_pwd = f.encrypt(pwd.encode()).decode()

     entries = load_vault(username)
     entries.append({"service": service, "username": uname, "password": encrypted_pwd}) # Store encrypted password
     save_vault(username, entries)
     print("Entry added.")

def view_vault_entries(username, vault_key, hashed_password): # Added key and hashed_password
     entries = load_vault(username)
     if not entries:
        print("No saved entries")
        return
     
     print("\n--- Your Entries ---")
     for i, entry in enumerate(entries, 1):
          # Initially display passwords as encrypted
          print(f"{i}. {entry['service']} - {entry['username']} / *** (Encrypted)")

     while True:
          decrypt_choice = input("Enter entry number to view password (or 'q' to quit): ")
          if decrypt_choice.lower() == 'q':
               break
          if decrypt_choice.isdigit():
               index = int(decrypt_choice) - 1
               if 0 <= index < len(entries):
                    # Ask for master password to decrypt
                    master_pwd_check = getpass.getpass("Enter your master password to decrypt: ")
                    if verify_password(master_pwd_check, hashed_password): # Use the passed hashed_password
                         try:
                              f = Fernet(vault_key.encode())
                              decrypted_pwd = f.decrypt(entries[index]['password'].encode()).decode()
                              print(f"\nDecrypted Password for {entries[index]['service']}: {decrypted_pwd}")
                         except Exception as e:
                              print(f"Error decrypting password: {e}. The key might be incorrect or data corrupted.")
                    else:
                         print("Incorrect master password.")
               else:
                    print("Invalid entry number.")
          else:
               print("Invalid input.")

def delete_vault_entry(username):
     entries = load_vault(username)
     if not entries:
          print("No entries to delete.")
          return
     
     print("\n--- Current Entries (for deletion) ---")
     for i, entry in enumerate(entries, 1):
        print(f"{i}. {entry['service']} - {entry['username']}")

     choice = input("Enter entry number to delete:  ")
     if choice.isdigit():
          index = int(choice) - 1
          if 0 <= index < len(entries):
               removed = entries.pop(index)
               save_vault(username, entries)
               print(f"Deleted entry for {removed['service']}.")
          else:
               print("Invalid entry number.")
     else:
          print("Invalid input.")


def vault_menu(user_data): 
     ensure_vault_dir()
     username = user_data['username']
     vault_key = user_data['vault_key']
     hashed_password = user_data['hashed_password'] # Get hashed_password for re-verification

     while True:
          print(f"\n--- {username}'s Vault ---")
          print("1. Add Entry")
          print("2. View Entries") # Added this display
          print("3. Delete Entry")
          print("4. Logout")
          choice = input("Select an option: ")

          if choice == "1":
               add_vault_entry(username, vault_key) # Pass vault_key
          elif choice == "2":
               view_vault_entries(username, vault_key, hashed_password) # Pass vault_key and hashed_password
          elif choice == "3":
               delete_vault_entry(username)
          elif choice == "4":
               print("Logged out.")
               break
          else:
               print("Invalid option.")


#Username and password
#create/enter credentials

USER_FILE = "users.json"

def load_users():
    if not os.path.exists(USER_FILE):
        return []
    with open(USER_FILE, "r") as f:
         return json.load(f)


def save_user(users):
	with open(USER_FILE, "w") as f:
		json.dump(users, f, indent=4)

def hash_password(password):
	return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
	return bcrypt.checkpw(password.encode(), hashed.encode())

def create_account():
	
    users = load_users()
    username = input("Choose a username: ")
				  
    if any(u["username"] == username for u in users):
        print("Username already exists.")
        return
    password = getpass.getpass("Create a password: ")
    hashed = hash_password(password)
    # Generate and store a Fernet key for the user's vault
    key = Fernet.generate_key().decode()
    users.append({"username": username, "hashed_password": hashed, "vault_key": key}) # Added vault_key
    save_user(users)
    print("Success! Account created.")

def login():
	
    users = load_users()
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    for user in users: 
        if user["username"] == username:
            if verify_password(password, user["hashed_password"]):
                print("Login successful!")
                return user     # Returns the entire user dictionary
            else:
                print("Incorrect password.")
                return None
    print("User not found.")
    return None

def main():
    while True:
        print("\n--- Password Manager ---")
        print("1. Create an Account")
        print("2. Login")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == ("1"):
            create_account()
        elif choice == "2":
            user_data = login() # user_data will be a dict or None
            if user_data:
                print(f"Welcome, {user_data['username']}!")
                vault_menu(user_data) # Pass the entire user_data dict
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()