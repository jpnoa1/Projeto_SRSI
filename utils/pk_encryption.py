import base64

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Ciphers a message with the public key
def cipher_with_public_key(message, pubkey):
    print("\nCiphering with the public key...")

    ciphertext = pubkey.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))
    return ciphertext


# Decipher a plaintext with the private key
def decipher_with_private_key(privkey, ciphertext):
    print("\nDeciphering with the private key...")
    plaintext = privkey.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Plaintext = " + str(base64.b64encode(plaintext)))
    return plaintext