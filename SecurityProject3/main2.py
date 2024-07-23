import argparse
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json


class PasswordManager:
    def __init__(self):
        self.passwords = {}

    def generate_secure_password(self, simple_password, key):
        cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(bytes(simple_password, 'utf-8'), AES.block_size))
        return base64.b64encode(encrypted).decode('utf-8')

    def save_password(self, name, comment, simple_password, key):
        secure_password = self.generate_secure_password(simple_password, key)
        self.passwords[name] = {'comment': comment, 'password': secure_password}

    def show_passwords(self):
        for name, info in self.passwords.items():
            print(f"Name: {name}, Comment: {info['comment']}, Encrypted Password: {info['password']}")

    def show_password(self, name, key):
        if name in self.passwords:
            info = self.passwords[name]
            cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC)
            decrypted = unpad(cipher.decrypt(base64.b64decode(info['password'])), AES.block_size)
            print(f"Name: {name}, Comment: {info['comment']}, Decrypted Password: {decrypted.decode('utf-8')}")
        else:
            print(f"Password with name '{name}' not found.")

    def update_password(self, name, key, new_simple_password):
        if name in self.passwords:
            self.passwords[name]['password'] = self.generate_secure_password(new_simple_password, key)
            print(f"Password with name '{name}' updated successfully.")
        else:
            print(f"Password with name '{name}' not found.")

    def delete_password(self, name):
        if name in self.passwords:
            del self.passwords[name]
            print(f"Password with name '{name}' deleted successfully.")
        else:
            print(f"Password with name '{name}' not found.")

    def save_to_file(self, filename, key):
        with open(filename, 'w') as file:
            json.dump(self.passwords, file, indent=2, ensure_ascii=False, default=str)
        # Encrypt the file content
        with open(filename, 'rb') as file:
            plaintext = file.read()
        cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        with open(filename, 'wb') as file:
            file.write(encrypted)

    def load_from_file(self, filename, key):
        # Decrypt the file content
        with open(filename, 'rb') as file:
            encrypted = file.read()
        cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        # Load passwords from the decrypted content
        self.passwords = json.loads(decrypted.decode('utf-8'))


def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    parser.add_argument("--newpass", help="Create a new password", nargs=4)
    parser.add_argument("--showpass", help="Show all passwords", action="store_true")
    parser.add_argument("--show", help="Show a specific password", nargs=2)
    parser.add_argument("--update", help="Update a password", nargs=3)
    parser.add_argument("--delete", help="Delete a password", nargs=1)
    parser.add_argument("--save", help="Save passwords to a file", nargs=2)
    parser.add_argument("--load", help="Load passwords from a file", nargs=2)

    args = parser.parse_args()

    password_manager = PasswordManager()

    if args.newpass:
        name, comment, simple_password, key = args.newpass
        password_manager.save_password(name, comment, simple_password, key)
    elif args.showpass:
        password_manager.show_passwords()
    elif args.show:
        name, key = args.show
        password_manager.show_password(name, key)
    elif args.update:
        name, key, new_simple_password = args.update
        password_manager.update_password(name, key, new_simple_password)
    elif args.delete:
        name = args.delete[0]
        password_manager.delete_password(name)
    elif args.save:
        filename, key = args.save
        password_manager.save_to_file(filename, key)
    elif args.load:
        filename, key = args.load
        password_manager.load_from_file(filename, key)
    else:
        print("Invalid command. Use --help for usage information.")


if __name__ == "__main__":
    main()
