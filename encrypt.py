import os
import base64
import hashlib
import pyaes


# Derivare cheie (AES-256)
def derive_key(password):
    return hashlib.sha256(password.encode()).digest()


# PKCS7 padding
def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


# PKCS7 unpadding
def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


# CRIPTARE
def encrypt(text, password):
    key = derive_key(password)
    iv = os.urandom(16)

    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)

    data = text.encode()
    padded = pkcs7_pad(data)

    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += aes.encrypt(block)

    return base64.b64encode(iv + ciphertext).decode()


# DECRIPTARE
def decrypt(token, password):
    raw = base64.b64decode(token)

    iv = raw[:16]
    ciphertext = raw[16:]

    key = derive_key(password)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)

    decrypted = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted += aes.decrypt(block)

    return pkcs7_unpad(decrypted).decode()


# MENIU
if __name__ == "__main__":
    print("1. Criptare")
    print("2. Decriptare")

    opt = input("Alege opțiunea: ")

    if opt == "1":
        parola = input("Parola: ")
        text = input("Text: ")
        encrypted = encrypt(text, parola)
        print("\n=== TEXT CRIPTAT ===")
        print(encrypted)

    elif opt == "2":
        parola = input("Parola: ")
        token = input("Text criptat: ")

        try:
            decrypted = decrypt(token, parola)
            print("\n=== TEXT DECRIPTAT ===")
            print(decrypted)
        except Exception as e:
            print("\n❌ Parola greșită sau text invalid!")

    else:
        print("Opțiune invalidă!")
