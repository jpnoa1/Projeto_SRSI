from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
from utils.pk_encryption import create_key_pair
import io

class Gateway:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.secret_key = None
        self.file = None


def generate_keys(self):
        # Gerar chaves RSA
        print("[INFO] A gerar chaves RSA")
        self.private_key = create_key_pair(2048)
        self.public_key = self.private_key.public_key()
        print("[INFO] Chaves RSA geradas.")
         # Chave secreta aleatória
        self.secret_key = os.urandom(32)  
        #encriptacao da chave privada
        encrypted_private_key = self.encrypt_private_key(self.private_key, self.secret_key)

        self.file = open("sk_storing", "w+")
        self.file.write(self.private_key)
        self.file.close()

        # Chave secreta aleatória
        self.secret_key = os.urandom(32)  
        #encriptacao da chave privada
        encrypted_private_key = self.encrypt_private_key(self.private_key, self.secret_key)
        print("[INFO] RSA keys generated and private key encrypted.")
        return encrypted_private_key



def main():
    # Configurar o socket do Gateway
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    server.listen(5)
    server.settimeout(1.0)  # Timeout de 1 segundo para evitar bloqueio

    print("[*] Gateway executando na porta 8080...")

    try:
        while True:
            try:
                # Aceitar conexões (com timeout)
                client_socket, client_address = server.accept()
                print(f"Conexão recebida de {client_address}")
                client_socket.send(b"Bem-vindo ao servidor!")
                client_socket.close()
            except socket.timeout:
                # Continuar o loop quando o timeout ocorre
                pass
    except KeyboardInterrupt:
        # Fechar o servidor ao pressionar Ctrl+C
        print("\nParando o servidor...")
        server.close()

if __name__ == "__main__":
    main()
