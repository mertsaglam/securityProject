from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

# 1) Generation of RSA Public-Private Key Pair
key_pair = RSA.generate(1024)
public_key = key_pair.publickey().export_key()
private_key = key_pair.export_key()
print("Public Key:\n", public_key.decode())
print("Private Key:\n", private_key.decode())


# 2) Generation of Symmetric Keys and Encryption/Decryption with RSA
symmetric_key = get_random_bytes(32)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
cipher_rsa = PKCS1_OAEP.new(key_pair)
decrypted_symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
print("Symmetric Key:\n", symmetric_key)
print("Encrypted Symmetric Key:\n", encrypted_symmetric_key)
print("Decrypted Symmetric Key:\n", decrypted_symmetric_key)

# 3) Generation and Verification of Digital Signature
message = "This is a sample message."
message_hash = hashlib.sha256(message.encode()).digest()
cipher_rsa = PKCS1_OAEP.new(key_pair)
digital_signature = cipher_rsa.encrypt(message_hash)
cipher_rsa = PKCS1_OAEP.new(key_pair)  # Use private key for decryption
decrypted_signature = cipher_rsa.decrypt(digital_signature)
new_message_hash = hashlib.sha256(message.encode()).digest()
is_correct = decrypted_signature == new_message_hash
print("Message:\n", message)
print("Hash of Message:\n", message_hash.hex())
print("Digital Signature:\n", digital_signature)
print("Decrypted Signature:\n", decrypted_signature)
print("Is Signature Correct?\n", is_correct)


# 4) AES Encryption/Decryption
message = "This is a sample message."
iv = get_random_bytes(16)
aes_key = get_random_bytes(32)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
decipher = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted_message = unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Ciphertext:\n", ciphertext)
print("Decrypted Message:\n", decrypted_message.decode())

# Change the IV and show different ciphertext for the same plaintext
new_iv = get_random_bytes(16)
new_cipher = AES.new(aes_key, AES.MODE_CBC, new_iv)
new_ciphertext = new_cipher.encrypt(pad(message.encode(), AES.block_size))
print("New Ciphertext:\n", new_ciphertext)

# 5) Message Authentication Codes (HMAC-SHA256)
hmac_key = get_random_bytes(32)
mac = hmac.new(hmac_key, message.encode(), hashlib.sha256)
new_key = hmac.new(hmac_key, "KS".encode(), hashlib.sha256).digest()
print("Message Authentication Code (HMAC-SHA256):\n", mac.digest())
print("New Key (HMAC-SHA256 of KS):\n", new_key)