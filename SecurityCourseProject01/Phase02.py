import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64

saved_salt = True


def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(password.encode())


def generate_key(password):
    global saved_salt
    if not saved_salt:
        # sakhte salt va save salt
        salt = secrets.token_bytes(16)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
        saved_salt = True
    else:
        salt = open("salt.salt", "rb").read()
    # sakht klid shakhsi sazi shode
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)
    print("File encrypted successfully")


def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("Password is incorrect")
        return
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    print("File decrypted successfully")


filename = input("Please Enter name of the file:  ")
password = input("Enter password:   ")
encrypt_or_decrypt = input("Enter 1 for encrypt and 2 for decrypt:   ")

if int(encrypt_or_decrypt) == 1:
    encrypt(filename, generate_key(password))
else:
    decrypt(filename, generate_key(password))