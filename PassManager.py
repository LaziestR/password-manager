#Group 7, Password Manager

import os
import json
import bcrypt
import getpass
import base64
import sys
from cryptography.fernet import Fernet

# GUI imports - only import if GUI mode is requested
try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                QStackedWidget, QTableWidget, QTableWidgetItem,
                                QMessageBox, QInputDialog, QHeaderView, QDialog,
                                QDialogButtonBox, QFormLayout)
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

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

def add_vault_entry_with_data(username, vault_key, service, uname, pwd):
     """GUI version of add_vault_entry that accepts parameters instead of prompting"""
     f = Fernet(vault_key.encode())
     encrypted_pwd = f.encrypt(pwd.encode()).decode()

     entries = load_vault(username)
     entries.append({"service": service, "username": uname, "password": encrypted_pwd})
     save_vault(username, entries)
     return True

def view_vault_entries(username, vault_key, hashed_password): # Added key and hashed_password
     entries = load_vault(username)
     if not entries:
        print("No saved entries")
        return
     
     print("\n--- Your Entries ---")
     for i, entry in enumerate(entries, 1):
          #display passwords as encrypted
          print(f"{i}. {entry['service']} - {entry['username']} / *** (Encrypted)")

     while True:
          decrypt_choice = input("Enter entry number to view password (or 'q' to quit): ")
          if decrypt_choice.lower() == 'q':
               break
          if decrypt_choice.isdigit():
               index = int(decrypt_choice) - 1
               if 0 <= index < len(entries):
                    # ask for master password to decrypt
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

def decrypt_password_for_gui(vault_key, encrypted_password):
     """Helper function to decrypt password for GUI"""
     try:
          f = Fernet(vault_key.encode())
          return f.decrypt(encrypted_password.encode()).decode()
     except Exception as e:
          return None

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

def delete_vault_entry_by_index(username, index):
     """GUI version of delete_vault_entry that accepts index parameter"""
     entries = load_vault(username)
     if 0 <= index < len(entries):
          removed = entries.pop(index)
          save_vault(username, entries)
          return True, f"Deleted entry for {removed['service']}."
     return False, "Invalid entry index."

def vault_menu(user_data): 
     ensure_vault_dir()
     username = user_data['username']
     vault_key = user_data['vault_key']
     hashed_password = user_data['hashed_password'] # Get hashed_password for re-verification

     while True:
          print(f"\n--- {username}'s Vault ---")
          print("1. Add Entry")
          print("2. View Entries")
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

def create_account_with_data(username, password):
    """GUI version of create_account that accepts parameters"""
    users = load_users()
    
    if any(u["username"] == username for u in users):
        return False, "Username already exists."
    
    hashed = hash_password(password)
    key = Fernet.generate_key().decode()
    users.append({"username": username, "hashed_password": hashed, "vault_key": key})
    save_user(users)
    return True, "Success! Account created."

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

def login_with_data(username, password):
    """GUI version of login that accepts parameters"""
    users = load_users()

    for user in users: 
        if user["username"] == username:
            if verify_password(password, user["hashed_password"]):
                return True, user     # Returns success and user dictionary
            else:
                return False, "Incorrect password."
    return False, "User not found."

def main_cli():
    """Command Line Interface main function"""
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

# GUI Classes (only defined if PyQt6 is available)
if GUI_AVAILABLE:
    
    class AddEntryDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Add New Entry")
            self.setModal(True)
            self.setFixedSize(400, 200)
            
            layout = QFormLayout()
            
            self.service_input = QLineEdit()
            self.username_input = QLineEdit()
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            
            layout.addRow("Service:", self.service_input)
            layout.addRow("Username:", self.username_input)
            layout.addRow("Password:", self.password_input)
            
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                     QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addRow(buttons)
            
            self.setLayout(layout)
        
        def get_data(self):
            return (self.service_input.text(), 
                    self.username_input.text(), 
                    self.password_input.text())

    class LoginWindow(QWidget):
        def __init__(self, main_window):
            super().__init__()
            self.main_window = main_window
            self.init_ui()
        
        def init_ui(self):
            layout = QVBoxLayout()
            layout.setSpacing(20)
            layout.setContentsMargins(50, 50, 50, 50)
            
            # Title
            title = QLabel("Password Manager")
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
            layout.addWidget(title)
            
            # Login section
            login_layout = QVBoxLayout()
            login_layout.setSpacing(10)
            
            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Username")
            self.username_input.setMinimumHeight(40)
            
            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText("Password")
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setMinimumHeight(40)
            self.password_input.returnPressed.connect(self.login)
            
            login_btn = QPushButton("Login")
            login_btn.setMinimumHeight(40)
            login_btn.clicked.connect(self.login)
            
            create_btn = QPushButton("Create Account")
            create_btn.setMinimumHeight(40)
            create_btn.clicked.connect(self.show_create_account)
            
            login_layout.addWidget(QLabel("Username:"))
            login_layout.addWidget(self.username_input)
            login_layout.addWidget(QLabel("Password:"))
            login_layout.addWidget(self.password_input)
            login_layout.addWidget(login_btn)
            login_layout.addWidget(create_btn)
            
            layout.addLayout(login_layout)
            layout.addStretch()
            self.setLayout(layout)
        
        def login(self):
            username = self.username_input.text().strip()
            password = self.password_input.text()
            
            if not username or not password:
                QMessageBox.warning(self, "Warning", "Please enter both username and password.")
                return
            
            # Use the CLI function directly
            success, result = login_with_data(username, password)
            
            if success:
                self.main_window.user_data = result
                self.main_window.switch_to_vault()
                self.username_input.clear()
                self.password_input.clear()
            else:
                QMessageBox.warning(self, "Login Failed", result)
        
        def show_create_account(self):
            self.main_window.switch_to_create_account()

    class CreateAccountWindow(QWidget):
        def __init__(self, main_window):
            super().__init__()
            self.main_window = main_window
            self.init_ui()
        
        def init_ui(self):
            layout = QVBoxLayout()
            layout.setSpacing(20)
            layout.setContentsMargins(50, 50, 50, 50)
            
            title = QLabel("Create New Account") # Title
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
            layout.addWidget(title)
            
            create_layout = QVBoxLayout() 
            # Create account section
            create_layout.setSpacing(10)
            
            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Choose a username")
            self.username_input.setMinimumHeight(40)
            
            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText("Create a password")
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setMinimumHeight(40)
            
            self.confirm_password_input = QLineEdit()
            self.confirm_password_input.setPlaceholderText("Confirm password")
            self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_password_input.setMinimumHeight(40)
            self.confirm_password_input.returnPressed.connect(self.create_account)
            
            create_btn = QPushButton("Create Account")
            create_btn.setMinimumHeight(40)
            create_btn.clicked.connect(self.create_account)
            
            back_btn = QPushButton("Back to Login")
            back_btn.setMinimumHeight(40)
            back_btn.clicked.connect(self.back_to_login)
            
            create_layout.addWidget(QLabel("Username:"))
            create_layout.addWidget(self.username_input)
            create_layout.addWidget(QLabel("Password:"))
            create_layout.addWidget(self.password_input)
            create_layout.addWidget(QLabel("Confirm Password:"))
            create_layout.addWidget(self.confirm_password_input)
            create_layout.addWidget(create_btn)
            create_layout.addWidget(back_btn)
            
            layout.addLayout(create_layout)
            layout.addStretch()
            self.setLayout(layout)
        
        def create_account(self):
            username = self.username_input.text().strip()
            password = self.password_input.text()
            confirm_password = self.confirm_password_input.text()
            
            if not username or not password:
                QMessageBox.warning(self, "Warning", "Please fill in all fields.")
                return
            
            if password != confirm_password:
                QMessageBox.warning(self, "Warning", "Passwords do not match.")
                return
            
            if len(password) < 6:
                QMessageBox.warning(self, "Warning", "Password must be at least 6 characters long.")
                return
            
            # Use the CLI function directly
            success, message = create_account_with_data(username, password)
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.clear_fields()
                self.main_window.switch_to_login()
            else:
                QMessageBox.warning(self, "Error", message)
        
        def clear_fields(self):
            self.username_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()
        
        def back_to_login(self):
            self.clear_fields()
            self.main_window.switch_to_login()

    class VaultWindow(QWidget):
        def __init__(self, main_window):
            super().__init__()
            self.main_window = main_window
            self.init_ui()
        
        def init_ui(self):
            layout = QVBoxLayout()
            layout.setSpacing(20)
            layout.setContentsMargins(20, 20, 20, 20)
            
            # Header
            header_layout = QHBoxLayout()
            self.title = QLabel()  # will be set when user logsin
            self.title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
            
            logout_btn = QPushButton("Logout")
            logout_btn.setMaximumWidth(100)
            logout_btn.clicked.connect(self.logout)
            
            header_layout.addWidget(self.title)
            header_layout.addStretch()
            header_layout.addWidget(logout_btn)
            layout.addLayout(header_layout)
            
            #buttons
            button_layout = QHBoxLayout()
            
            add_btn = QPushButton("Add Entry")
            add_btn.clicked.connect(self.add_entry)
            
            delete_btn = QPushButton("Delete Entry")
            delete_btn.clicked.connect(self.delete_entry)
            
            refresh_btn = QPushButton("Refresh")
            refresh_btn.clicked.connect(self.load_entries)
            
            button_layout.addWidget(add_btn)
            button_layout.addWidget(delete_btn)
            button_layout.addWidget(refresh_btn)
            button_layout.addStretch()
            
            layout.addLayout(button_layout)
            
            #Table
            self.table = QTableWidget()
            self.table.setColumnCount(4)
            self.table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.setAlternatingRowColors(True)
            
            layout.addWidget(self.table)
            self.setLayout(layout)
        
        def set_user(self, user_data):
            self.user_data = user_data
            self.title.setText(f"{user_data['username']}'s Vault")
            self.load_entries()
        
        def load_entries(self):
            # CLI function is being used
            entries = load_vault(self.user_data['username'])
            self.table.setRowCount(len(entries))
            
            for i, entry in enumerate(entries):
                self.table.setItem(i, 0, QTableWidgetItem(entry['service']))
                self.table.setItem(i, 1, QTableWidgetItem(entry['username']))
                self.table.setItem(i, 2, QTableWidgetItem("••••••••"))
                
                # View password button
                view_btn = QPushButton("View")
                view_btn.clicked.connect(lambda checked, row=i: self.view_password(row))
                self.table.setCellWidget(i, 3, view_btn)
        
        def add_entry(self):
            dialog = AddEntryDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                service, username, password = dialog.get_data()
                
                if not service or not username or not password:
                    QMessageBox.warning(self, "Warning", "Please fill in all fields.")
                    return
                
                # CLI is being used
                success = add_vault_entry_with_data(
                    self.user_data['username'],
                    self.user_data['vault_key'],
                    service, username, password
                )
                
                if success:
                    QMessageBox.information(self, "Success", "Entry added successfully!")
                    self.load_entries()
                else:
                    QMessageBox.warning(self, "Error", "Failed to add entry.")
        
        def view_password(self, row):
            # Ask for master password
            password, ok = QInputDialog.getText(
                self, "Master Password", 
                "Enter your master password to view the password:",
                QLineEdit.EchoMode.Password
            )
            
            if not ok or not password:
                return
            
            #use CLI verify_password function
            if not verify_password(password, self.user_data['hashed_password']):
                QMessageBox.warning(self, "Error", "Incorrect master password.")
                return
            
            #Get encrypted password using CLI function
            entries = load_vault(self.user_data['username'])
            if row < len(entries):
                encrypted_password = entries[row]['password']
                # Use the CLI helper function
                decrypted_password = decrypt_password_for_gui(
                    self.user_data['vault_key'], encrypted_password
                )
                
                if decrypted_password:
                    QMessageBox.information(
                        self, "Password", 
                        f"Password for {entries[row]['service']}:\n{decrypted_password}"
                    )
                else:
                    QMessageBox.warning(self, "Error", "Failed to decrypt password.")
        
        def delete_entry(self):
            current_row = self.table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select an entry to delete.")
                return
            
            # Use CLI functon to get entries for display
            entries = load_vault(self.user_data['username'])
            service_name = entries[current_row]['service']
            
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete the entry for '{service_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                #use the CLI function directly
                success, message = delete_vault_entry_by_index(
                    self.user_data['username'], current_row
                )
                
                if success:
                    QMessageBox.information(self, "Success", message)
                    self.load_entries()
                else:
                    QMessageBox.warning(self, "Error", message)
        
        def logout(self):
            reply = QMessageBox.question(
                self, "Logout",
                "Are you sure you want to logout?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.main_window.switch_to_login()

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.user_data = None
            self.init_ui()
        
        def init_ui(self):
            self.setWindowTitle("Password Manager")
            self.setGeometry(100, 100, 800, 600)
            
            # Create stacked widget to switch between windows
            self.stacked_widget = QStackedWidget()
            self.setCentralWidget(self.stacked_widget)
            
            # Create windows which all use CLI functions directly
            self.login_window = LoginWindow(self)
            self.create_account_window = CreateAccountWindow(self)
            self.vault_window = VaultWindow(self)
            
            # Add windows to stack
            self.stacked_widget.addWidget(self.login_window)      
            self.stacked_widget.addWidget(self.create_account_window)
            self.stacked_widget.addWidget(self.vault_window)    
            
            # Start with login window
            self.stacked_widget.setCurrentIndex(0)
        
        def switch_to_login(self):
            self.stacked_widget.setCurrentIndex(0)
        
        def switch_to_create_account(self):
            self.stacked_widget.setCurrentIndex(1)
        
        def switch_to_vault(self):
            self.vault_window.set_user(self.user_data)
            self.stacked_widget.setCurrentIndex(2)

    def main_gui():
        """GUI main function that uses CLI backend"""
        ensure_vault_dir()  # Use CLI function
        
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec())

def main():
    """Main function with mode selection"""
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode == 'gui':
            if not GUI_AVAILABLE:
                print("GUI mode requested but PyQt6 is not installed.")
                print("Please install PyQt6: pip install PyQt6")
                print("Falling back to CLI mode...")
                main_cli()
            else:
                main_gui()
        elif mode == 'cli':
            main_cli()
        else:
            print("Invalid mode. Use 'gui' or 'cli'")
            print("Usage: python PassManager.py [gui|cli]")
    else:
        # Default behavior - ask user for preference
        print("Password Manager")
        print("Select interface mode:")
        print("1. Command Line Interface (CLI)")
        if GUI_AVAILABLE:
            print("2. Graphical User Interface (GUI)")
        else:
            print("2. GUI (Not available - PyQt6 not installed)")
        
        choice = input("Choose mode (1 or 2): ").strip()
        
        if choice == "1":
            main_cli()
        elif choice == "2":
            if GUI_AVAILABLE:
                main_gui()
            else:
                print("GUI mode not available. PyQt6 is not installed.")
                print("Please install PyQt6: pip install PyQt6")
                print("Starting CLI mode instead...")
                main_cli()
        else:
            print("Invalid choice. Starting CLI mode...")
            main_cli()

if __name__ == "__main__":
    main()

#end 