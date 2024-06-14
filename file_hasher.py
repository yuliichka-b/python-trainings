from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt


def encrypt_file(file_path, password, key_file_path=None):
    if key_file_path is None:
        key_file_path = file_path + ".key"

    key, salt = derive_key(password)
    f = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = f.encrypt(data)

    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

    with open(key_file_path, 'wb') as key_file:
        key_file.write(salt)
        key_file.write(f.encrypt(key))


def decrypt_file(file_path, password, key_file_path=None):
    if key_file_path is None:
        key_file_path = file_path + ".key"

    with open(key_file_path, 'rb') as key_file:
        salt = key_file.read(16)
        encrypted_key = key_file.read()

    key, _ = derive_key(password, salt)
    f = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    decrypted_key = f.decrypt(encrypted_key)
    decrypt_f = Fernet(decrypted_key)
    decrypted_data = decrypt_f.decrypt(data)

    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

    os.remove(key_file_path)


def main():
    file_path = input("Enter the path of the file: ")
    if os.path.isfile(file_path):
        password = getpass("Enter the password: ")
        action = input("Do you want to encrypt or decrypt the file? (encrypt(e)/decrypt(d)): ")
        if action.lower() in ("encrypt", 'e', '1'):
            encrypt_file(file_path, password)
            print("File encrypted successfully. A key file has been created. Keep it safe.")
        elif action.lower() in ("decrypt", 'd', '2'):
            key_path = input("Enter the path to the key of the file (without .key extension) "
                             "(blank if same as file):")
            key_path = None if key_path == "" else key_path
            decrypt_file(file_path, password, key_path)
            print("File decrypted successfully.")
        else:
            print("Invalid action. Please enter 'encrypt' or 'decrypt'.")
    else:
        print("File not found.")


if __name__ == "__main__":
    main()
