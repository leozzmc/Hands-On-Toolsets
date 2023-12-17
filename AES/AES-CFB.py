import hashlib

def generate_key(password, salt):
    key = hashlib.md5(password.encode('utf-8') + salt).digest()
    return key

def aes_cfb_encrypt(key, iv, plaintext):
    ciphertext = b""
    prev_block = iv

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        encrypted_block = bytes(a ^ b for a, b in zip(block, prev_block))
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext

def aes_cfb_decrypt(key, iv, ciphertext):
    decrypted_text = b""
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = bytes(a ^ b for a, b in zip(block, prev_block))
        decrypted_text += decrypted_block
        prev_block = block

    return decrypted_text

def main():
    password = input("Enter password: ")
    plaintext = input("Enter plaintext: ")

    # Add salt for key derivation
    salt = b'some_salt'

    global_key = generate_key(password, salt)

    # Initialize IV (Initialization Vector)
    iv = b'initial_vector'

    encrypted_text = aes_cfb_encrypt(global_key, iv, plaintext.encode('utf-8'))
    print("Encrypted:", encrypted_text)

    decrypted_text = aes_cfb_decrypt(global_key, iv, encrypted_text)
    print("Decrypted:", decrypted_text.decode('utf-8'))

if __name__ == "__main__":
    main()
