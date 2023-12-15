from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import getpass  # 用於安全輸入密碼

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
    # 輸入密碼
    password = getpass.getpass("請輸入密碼: ")

    # 使用 PBKDF2 從密碼和鹽生成金鑰
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # 輸入要加密的明文
    plaintext = input("請輸入要加密的明文: ").encode('utf-8')

    # 加密
    encrypted_text = aes_encrypt(key, plaintext)
    print("加密後:", encrypted_text.decode('utf-8'))

    # 解密
    decrypted_text = aes_decrypt(key, encrypted_text)
    print("解密後:", decrypted_text.decode('utf-8'))

if __name__ == "__main__":
    main()
