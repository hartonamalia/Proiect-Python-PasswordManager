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
        print(self.db_path)
        with open(self.db_path, 'w') as f:
            print(self.db_path)
            f.write(encrypted_data)

    def add_password(self, website, username, password):
        if website not in self.passwords:
            self.passwords[website] = []

        self.passwords[website].append({'username': username, 'password': password})
        self.save_passwords()

    def get_password(self, website):
        return self.passwords.get(website, {})

def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    parser.add_argument('master_password', help='Master password for encryption/decryption')

    args, unknown_args = parser.parse_known_args()

    password_manager = PasswordManager()
    if password_manager.decrypt_data(password_manager.master_password) != args.master_password:
        print("Wrong password!")
        return 0


if __name__ == "__main__":
    main()
    #password_manager = PasswordManager()
    #print(password_manager.master_password)