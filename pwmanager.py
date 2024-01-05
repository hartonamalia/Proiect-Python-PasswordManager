import yaml
import argparse
from cryptography.fernet import Fernet
import json
import os


class PasswordManager:

    def __init__(self, db_path='pwmanager.db'):
        self.master_password = None
        self.db_path = db_path
        self.key = self.load_or_create_key()

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


if __name__ == "__main__":
    password_manager = PasswordManager("1234")
    print(password_manager.encrypt_data("1234"))