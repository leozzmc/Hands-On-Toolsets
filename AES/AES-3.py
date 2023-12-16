import argparse
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

KEY_FILE = "aes_key.txt"

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,  # 256 bits
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def save_key_to_file(key):
    with open(KEY_FILE, 'wb') as file:
        file.write(urlsafe_b64encode(key))

def load_key_from_file():
    try:
        with open(KEY_FILE, 'rb') as file:
            return urlsafe_b64decode(file.read())
    except FileNotFoundError:
        return None

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    result = urlsafe_b64encode(iv + ciphertext)
    return result

def aes_decrypt(key, ciphertext):
    data = urlsafe_b64decode(ciphertext)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    parser = argparse.ArgumentParser(description="AES Encryption/Decryption Tool")
    parser.add_argument("--encrypt", help="Encrypt the given message")
    parser.add_argument("--decrypt", help="Decrypt the given message")
    parser.add_argument("--save_to_file", help="Save the encrypted message to a file")

    args = parser.parse_args()

    password = getpass("Enter password: ")
    salt = os.urandom(16)

    # 檢查文件中是否已經有金鑰，如果有，則讀取，否則生成一個新的金鑰
    global_key = load_key_from_file()
    if global_key is None:
        global_key = generate_key(password, salt)
        save_key_to_file(global_key)

    if args.encrypt:
        plaintext = args.encrypt.encode('utf-8')
        encrypted_text = aes_encrypt(global_key, plaintext)
        
        if args.save_to_file:
            with open(args.save_to_file, 'wb') as file:
                file.write(encrypted_text)
            print(f"Encrypted message saved to {args.save_to_file}")

        print("Encrypted:", encrypted_text.decode('utf-8'))

    elif args.decrypt:
        if os.path.exists(args.decrypt):
            with open(args.decrypt, 'rb') as file:
                encrypted_text = file.read()
        else:
            encrypted_text = args.decrypt

        decrypted_text_hex = aes_decrypt(global_key, encrypted_text)
        
        try:
            # 嘗試使用 utf-8 解碼
            decrypted_text = decrypted_text_hex.decode('utf-8')
        except UnicodeDecodeError:
            print("Unable to decode using utf-8.")
            decrypted_text = decrypted_text_hex.decode('utf-8', 'replace')  # 使用替代字符替換無效的字節
        
        print("Decrypted:", decrypted_text)

    else:
        print("Please provide either --encrypt or --decrypt option.")

if __name__ == "__main__":
    main()
