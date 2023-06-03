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


