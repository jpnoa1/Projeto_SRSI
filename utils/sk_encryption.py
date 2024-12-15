import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_with_sk(message, mode, key, iv=None, nonce=None):
    print("\nEncrypting with AES, 256-bit key, mode " + mode)

    print("Data:" + str(message))

    # AES works on blocks of 128bits (32 bytes) so we need to make user the message is multiple of the block lenght
    if len(message) % 16 != 0:
        # handling the padding of the messages
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddeddata = padder.update(message)
        paddeddata += padder.finalize()
        print("Data (padded):" +  str(paddeddata))
        message = paddeddata

    print("KEY = " + str(base64.b64encode(key)))
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    encryptor = cipher.encryptor()
    print("[INFO] Encryption successful")
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return nonce + ciphertext
    
    
    
def decrypt_with_sk(encrypted_data, mode, key):
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    print("\nDecrypting with AES, 256-bit key, mode " + mode)
    print("KEY = " + str(base64.b64encode(key)))
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print("[INFO] Decryption successfull, \nPlaintext = " + str(plaintext.decode('utf-8')))
    return str(plaintext.decode('utf-8'))
