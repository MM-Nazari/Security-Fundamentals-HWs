# Used libraries:
import argparse  # For command line argument processing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For deriving key
from cryptography.hazmat.backends import default_backend  # For selecting cryptography backend
from cryptography.hazmat.primitives import hashes  # For using hash functions
from base64 import urlsafe_b64encode, urlsafe_b64decode  # For performing Base64 operations
import os  # For generating random numbers and interacting with files
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import random


class PasswordManager:
    """
    PasswordManager class for managing encrypted passwords.
    """

    def __init__(self, key):
        """
        Initializes the PasswordManager with a master key.

        Parameters:
        - key (str): The master key for password encryption and decryption.
        """
        self.key = key
        # self.cipher_suite = Fernet(key)

    '''
   def encrypt_password(self, password):
        """
        Encrypts a password using PBKDF2 key derivation and AES encryption.

        Parameters:
        - password (str): The password to be encrypted.

        Returns:
        - str: The encrypted password.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(self.key.encode()))
        cipher_text = urlsafe_b64encode(password.encode())
        return key + cipher_text

    def decrypt_password(self, encrypted_password):
        """
        Decrypts an encrypted password using the master key.

        Parameters:
        - encrypted_password (str): The encrypted password.

        Returns:
        - str: The decrypted password.
        """
        key = urlsafe_b64encode(self.key.encode())
        try:
            # Ensure proper padding for the base64-encoded string
            padding = b'=' * (4 - (len(encrypted_password) % 4))
            padded_encrypted_password = (encrypted_password + padding).encode()

            # Decode the properly padded base64-encoded string
            cipher_text = urlsafe_b64decode(padded_encrypted_password)

            # Decrypt the cipher text
            decrypted = cipher_text[len(key):].decode('utf-8')

            # Return the decrypted password as a string
            return decrypted
        except Exception as e:
            print(f"Error during decryption: {e}")
            return None

    '''
    '''
        def encrypt_password(self, password):
        return Fernet(self.key).encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return Fernet(self.key).decrypt(encrypted_password.encode()).decode()
    
    '''
    '''
        def encrypt_password(self, password):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_password = self._pad(password.encode())
        encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_password).decode()

    def decrypt_password(self, encrypted_password):
        decoded_encrypted = base64.b64decode(encrypted_password)
        iv, encrypted_password = decoded_encrypted[:16], decoded_encrypted[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        return self._unpad(decrypted_password).decode()

    def _pad(self, data):
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data):
        padding_length = data[-1]
        return data[:-padding_length]
    '''

    def encrypt_password(self, password):
        """
        رمزنگاری یک گذرواژه با استفاده از مشتق‌کننده کلید PBKDF2 و رمزنگاری AES.

        پارامترها:
        - password (str): گذرواژه‌ای که باید رمزنگاری شود.

        بازگشت:
        - str: گذرواژه رمزنگاری شده.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(self.key.encode()))
        cipher_text = urlsafe_b64encode(password.encode())
        return key + cipher_text

    def decrypt_password(self, encrypted_password):
        """
        رمزگشایی یک گذرواژه رمزنگاری شده با استفاده از کلید اصلی.

        پارامترها:
        - encrypted_password (str): گذرواژه رمزنگاری شده.

        بازگشت:
        - str: گذرواژه رمزگشایی شده.
        """
        key = urlsafe_b64encode(self.key.encode())
        cipher_text = urlsafe_b64decode(encrypted_password)
        return urlsafe_b64decode(cipher_text[len(key):]).decode()

    def save_password(self, name, comment, password):
        """
        Saves a new password entry to a text file.

        Parameters:
        - name (str): The name associated with the password.
        - comment (str): A comment or description for the password.
        - password (str): The password to be saved.
        """
        encrypted_password = self.encrypt_password(password)
        with open('passwords.txt', 'a') as file:
            file.write(f"{name}:{comment}:{encrypted_password}\n")

    def generate_random_number(self, start, end):
        """
        Generates a random integer in the range [start, end].

        Parameters:
        - start (int): The start of the range (inclusive).
        - end (int): The end of the range (inclusive).

        Returns:
        - int: A random integer within the specified range.
        """
        return random.randint(start, end)

    def save_test(self):

        for i in range(1, 10001):
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=100000,
                backend=default_backend()
            )
            key = urlsafe_b64encode(kdf.derive(str(i).encode()))
            cipher_text = urlsafe_b64encode("0000".encode())
            encrypted_password = key + cipher_text
            with open('test.txt', 'a') as file:
                file.write(f"{encrypted_password}\n")

    def show_passwords(self):
        """
        Shows all passwords stored in the text file.
        """
        with open('passwords.txt', 'r') as file:
            for line in file:
                data = line.strip().split(':')
                if len(data) >= 3:
                    name, comment, password = data[:3]
                    # decrypted_password = self.decrypt_password(password)
                    print(f"Name: {name}, Comment: {comment}, Password: {password}")
                else:
                    print(f"Invalid line: {line}")

    def show_password(self, name):
        """
        Shows details of a specific password.

        Parameters:
        - name (str): The name associated with the password.
        """
        with open('passwords.txt', 'r') as file:
            for line in file:
                data = line.strip().split(':')
                if data[0] == name:
                    # decrypted_password = self.decrypt_password(data[2])
                    print(f"Name: {data[0]}, Comment: {data[1]}, Password: {data[2]}")

    def update_password(self, name, new_password):
        """
        Updates the password for a specific entry.

        Parameters:
        - name (str): The name associated with the password.
        - new_password (str): The new password to be updated.
        """
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        with open('passwords.txt', 'w') as file:
            for line in lines:
                data = line.strip().split(':')
                if data[0] == name:
                    updated_line = f"{name}:{data[1]}:{self.encrypt_password(new_password).decode()}\n"
                    file.write(updated_line)
                else:
                    file.write(line)

    @staticmethod
    def delete_password(names):
        """
        Deletes password entries for specified names.

        Parameters:
        - names (list): A list of names for passwords to be deleted.
        """
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        with open('passwords.txt', 'w') as file:
            for line in lines:
                data = line.strip().split(':')
                if data[0] not in names:
                    file.write(line)


def main():
    """
    Main function for handling command-line interface operations.
    """
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    parser.add_argument("--newpass", help="Create a new password", nargs=3)
    # parser.add_argument("--c", help="Comment for the password", nargs=1)
    # parser.add_argument("--key", help="User simple password", nargs=1)
    parser.add_argument("--showpass", help="Show all passwords", action="store_true")
    parser.add_argument("--sel", help="Show a specific password", nargs=1)
    parser.add_argument("--update", help="Update a password", nargs=1)
    parser.add_argument("--delete", help="Delete a password", nargs='+')  # Allow one or more names
    parser.add_argument("--test", help="run test part", action="store_true")

    args = parser.parse_args()

    key = input("Enter your master password: ")
    password_manager = PasswordManager(key)

    '''
        if args.newpass and args.c and args.key:
        name = args.newpass
        comment = args.c
        user_password = args.key
        password_manager.save_password(name, comment, user_password)
    '''

    if args.newpass:
        name, comment, simple_password = args.newpass
        password_manager.save_password(name, comment, simple_password)
    elif args.showpass:
        password_manager.show_passwords()
    elif args.sel:
        name = args.sel[0]
        password_manager.show_password(name)
    elif args.update:
        name = args.update[0]
        new_password = input("Enter the new password: ")
        password_manager.update_password(name, new_password)
    elif args.delete:
        names = args.delete
        password_manager.delete_password(names)
    elif args.test:
        password_manager.save_test()
    else:
        print("Invalid command. Use --help for usage information.")


if __name__ == "__main__":
    main()
