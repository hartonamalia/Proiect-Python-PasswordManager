import yaml
import argparse
from cryptography import fernet
from cryptography.fernet import Fernet
import json
import os


class PasswordManager:

    def __init__(self, db_path='pwmanager.db'):
        self.master_password = None
        self.db_path = db_path
        self.key = self.load_or_create_key()
        self.passwords = self.load_passwords()
        self.load_master_password()

    def load_master_password(self):
        try:
            with open('config.yaml', 'r') as file:
                config = yaml.safe_load(file)
            self.master_password = config['master_password']
        except Exception as e:
            print(f"An error occurred: {e}")
            raise

    def load_or_create_key(self):
        key_file = 'key.key'
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            print(f"An error occurred: {e}")
            raise

    def encrypt_data(self, data):
        cipher = Fernet(self.key)
        return cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, data):
        cipher = Fernet(self.key)
        return cipher.decrypt(data).decode()

    def load_passwords(self):
        passwords_dict = {}

        if os.path.exists(self.db_path):
            with open(self.db_path, 'rb') as f:
                encrypted_data = f.read()

                if encrypted_data:
                    try:
                        decrypted_data = self.decrypt_data(encrypted_data)
                        passwords_dict = json.loads(decrypted_data)
                    except fernet.InvalidToken:
                        print("Invalid token, cannot decrypt the passwords.")
                    except json.JSONDecodeError:
                        print("Decrypted data is not valid JSON.")

        return passwords_dict

    def save_passwords(self):
        encrypted_data = self.encrypt_data(json.dumps(self.passwords))
        with open(self.db_path, 'w') as f:
            f.write(encrypted_data)

    def add_password(self, website, username, password):
        if website not in self.passwords:
            self.passwords[website] = []

        self.passwords[website].append({'username': username, 'password': password})
        self.save_passwords()

    def get_password(self, website):
        return self.passwords.get(website, {})

    def remove_website(self, website):
        if website in self.passwords:
            del self.passwords[website]
            self.save_passwords()

    def remove_website_user(self, website, username):
        if website in self.passwords:
            updated_credentials = [credential for credential in self.passwords[website] if
                                   credential['username'] != username]
            self.passwords[website] = updated_credentials
            self.save_passwords()

    def list_website_passwords(self):
        for website, credentials_list in self.passwords.items():
            for credential in credentials_list:
                print(f"Website: {website}, Username: {credential['username']}, Password: {credential['password']}")
            print()

def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    parser.add_argument('master_password', help='Master password for encryption/decryption')
    parser.add_argument('-add', nargs=3, metavar=('website', 'username', 'password'), help='Add a new password entry')
    parser.add_argument('-get', metavar='website', help='Get password for a specific website')
    parser.add_argument('-remove', metavar='website', help='Remove password for a specific website')
    parser.add_argument('-remove_user', nargs=2, metavar=('website', 'username'),
                        help='Remove a specific user for a website')
    parser.add_argument('-list', action='store_true', help='List all passwords')


    args, unknown_args = parser.parse_known_args()

    password_manager = PasswordManager()
    if password_manager.decrypt_data(password_manager.master_password) != args.master_password:
        print("Wrong password!")
        return 0

    if not (args.add or args.get or args.remove or args.list or args.remove_user):
        print("Invalid operation. Use -add, -get, -remove, -remove_user or -list.")
        return 0

    if args.add:
        website, username, password = args.add
        if password_manager.passwords.get(website):
            for credential in password_manager.passwords[website]:
                if username == credential['username']:
                    print("An account with this username for this website already exists")
                    return 0
        password_manager.add_password(website, username, password)
        print(f"Password added for {website}")
    elif args.get:
        website = args.get
        if website not in password_manager.passwords:
            print("No matching website found.")
            return 0
        credentials = password_manager.get_password(website)
        for credential in credentials:
            print(f"Website: {website}, Username: {credential['username']}, Password: {credential['password']}")
    elif args.remove:
        website = args.remove
        if website not in password_manager.passwords:
            print("No matching website found.")
            return 0
        password_manager.remove_website(website)
        print(f"Password removed for {website}")
    elif args.list:
        password_manager.list_website_passwords()


if __name__ == "__main__":
    main()
    #password_manager = PasswordManager()
    #print(password_manager.master_password)