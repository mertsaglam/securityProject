import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac



def public_private_generator(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    # Derive the public key
    public_key = private_key.public_key()

    # To get the key in bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(private_bytes.decode())
    print(public_bytes.decode())
    with open(username + "_private.pem", "wb") as f:
        f.write(private_bytes)
    with open(username + "_public.pem", "wb") as f:
        f.write(public_bytes)
    print("Keys generated for " + username + "!")


def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key


# Generation of Symmetric Key
def create_symmetric_key():
    # Generate a 256-bit symmetric key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
    )
    symmetric_key = kdf.derive(b"my secret password")
    return symmetric_key


def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_symmetric_key


def decrypt_symmetric_key(encrypted_symmetric_key, private_key):
    decrypted_symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_symmetric_key

def generate_signature(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    

def generate_aes_key():
    aes_key = get_random_bytes(16)
    return aes_key


def encrypt_message_aes(message,key,IV):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext

def decrypt_message_aes(ciphertext,key,IV):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def generate_hmac_key(symmetric_key):
    h = hmac.new(symmetric_key, digestmod=hashlib.sha256)
    new_key = h.digest()
    return new_key



def part_4():
    message = b"Hello World! This is a message more than 100 characters. I need more characters to complete 100 character limit."
    aes_key = generate_aes_key()
    IV = get_random_bytes(16) # Generate a random IV
    ciphertext = encrypt_message_aes(message, aes_key, IV)
    print("Ciphertext:", base64.b64encode(ciphertext).decode())
    plaintext = decrypt_message_aes(ciphertext, aes_key, IV)
    print("Decrypted message:", plaintext.decode())
    
    # Now change the IV and show the ciphertext is different
    IV2 = get_random_bytes(16)
    ciphertext2 = encrypt_message_aes(message, aes_key, IV2)
    print("Ciphertext with different IV:", base64.b64encode(ciphertext2).decode())




def first_two_part():
    username = input("Enter username: ")
    public_private_generator(username)
    symmetric_key = create_symmetric_key()
    public_key = load_public_key(username + "_public.pem")
    private_key = load_private_key(username + "_private.pem")
    encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, public_key)
    decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, private_key)
    print("Symmetric Key:", symmetric_key)
    print("Encrypted Symmetric Key:", base64.b64encode(encrypted_symmetric_key).decode())
    print("Decrypted Symmetric Key:", decrypted_symmetric_key)
    

def part_3():
    username = input("Enter username: ")
    public_key = load_public_key(username + "_public.pem")
    private_key = load_private_key(username + "_private.pem")
    #generate a message length more than 100 characters
    message = b"Hello World! This is a message more than 100 characters. I need more characters to complete 100 character limit."
    signature = generate_signature(message, private_key)
    print("Signature:", base64.b64encode(signature).decode())
    print("Verification:", verify_signature(message, signature, public_key))
def main():
    # 1) Generation of RSA Public-Private Key Pair
    username = input("Enter username: ")
    public_private_generator(username)

    # 2) Generation of Symmetric keys
    symmetric_key = generate_aes_key()
    public_key = load_public_key(f"{username}_public.pem")
    encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, public_key)
    private_key = load_private_key(f"{username}_private.pem")
    decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, private_key)

    print("Symmetric Key:", base64.b64encode(symmetric_key).decode())
    print("Encrypted Symmetric Key:", base64.b64encode(encrypted_symmetric_key).decode())
    print("Decrypted Symmetric Key:", base64.b64encode(decrypted_symmetric_key).decode())

    # 3) Generation and Verification of Digital Signature
    message = b"Hello World! This is a message more than 100 characters. I need more characters to complete 100 character limit."
    signature = generate_signature(message, private_key)
    print("Signature:", base64.b64encode(signature).decode())
    print("Verification:", verify_signature(message, signature, public_key))

    # 4) AES Encryption/Decryption
    IV = get_random_bytes(16)
    ciphertext = encrypt_message_aes(message, symmetric_key, IV)
    print("Ciphertext:", base64.b64encode(ciphertext).decode())
    plaintext = decrypt_message_aes(ciphertext, symmetric_key, IV)
    print("Decrypted message:", plaintext.decode())

    # 5) Message Authentication Codes
    hmac_key = generate_hmac_key(symmetric_key)
    print("HMAC Key:", base64.b64encode(hmac_key).decode())


if __name__ == "__main__":
    main()

