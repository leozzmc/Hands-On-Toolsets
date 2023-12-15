from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_key(password, salt):
    # 使用 PBKDF2 演算法從密碼和鹽生成金鑰
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
    # 產生一個隨機的 IV (Initialization Vector)
    iv = os.urandom(16)
    
    # 使用 AES-CFB 模式初始化 Cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # 建立 Encryptor
    encryptor = cipher.encryptor()
    
    # 加密明文
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # 將 IV 和密文合併並進行 Base64 編碼
    result = urlsafe_b64encode(iv + ciphertext)
    
    return result

def aes_decrypt(key, ciphertext):
    # 將 Base64 解碼
    data = urlsafe_b64decode(ciphertext)
    
    # 提取 IV 和密文
    iv = data[:16]
    ciphertext = data[16:]
    
    # 使用 AES-CFB 模式初始化 Cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # 建立 Decryptor
    decryptor = cipher.decryptor()
    
    # 解密密文
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

# 使用 PBKDF2 從密碼和鹽生成金鑰
password = "your_password"
salt = os.urandom(16)
key = generate_key(password, salt)

# 要加密的明文
plaintext = b"Hello, AES!"

# 加密
encrypted_text = aes_encrypt(key, plaintext)
print("加密後:", encrypted_text)

# 解密
decrypted_text = aes_decrypt(key, encrypted_text)
print("解密後:", decrypted_text.decode('utf-8'))
