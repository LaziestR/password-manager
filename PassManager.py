#Group 7, Password Manager

import os
import json
import bcrypt
import getpass

VAULT_DIR = "vault"

def ensure_vault_dir():
     if not os.path.exists(VAULT_DIR):
          os.markedirs(VAULT_DIR)

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

def add_vault_entry(username):
     service = input("Service name: ")
     uname = input("Username: ")
     pwd = getpass.getpass("Password: ")

     entries = load_vault(username)
     entries.append({"service": service, "username": uname, "password": pwd}) 
     save_vault(username, entries)
     print("Entry added.")

def view_vault_entries(username):
     entries = load_vault(username)
     if not entries:
        print("No saved entries")
        return
     for i, entry in enumerate(entries, 1):
          print(f"{i}. {entry['service']} - {entry['username']} / {entry['password']}")

def delete_vault_entry(username):
     entries = load_vault(username)
     if not entries:
          print("No entries to delete.")
          return
     view_vault_entries(username)
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


def vault_menu(username):
     ensure_vault_dir()
     while True:
          print(f"\n--- {username}'s Vault ---")
          print("1. Add Entry")
          print("3. Delete Entry")
          print("4. Logout")
          choice = input("Select an option: ")

          if choice == "1":
               add_vault_entry(username)
          elif choice == "2":
               view_vault_entries(username)
          elif choice == "3":
               delete_vault_entry(username)
          elif choice == "4":
               print("Logged out.")
               break
          else:
               print("Invalid option.")




#Username and password
#create/enter credentials

import json
import bcrypt
import os
import getpass

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
    users.append({"username": username, "hashed_password": hashed})
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
                return username     #returns username for next steps
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
            user = login()
            if user:
                print(f"Welcome, {user}!")
                vault_menu(user)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()