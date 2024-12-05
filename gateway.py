from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
from cryptography import x509

class Gateway:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.secret_key = None


def generate_keys(self):
        print("[INFO] A gerar chaves RSA")
        input_password = input("Enter the password to protect the private key: ")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        # Chave secreta aleatória
        #stantby self.secret_key = os.urandom(32)  
        #encriptacao da chave privada
        
        with open("keys/gateway_key.pem", "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(input_password.encode('ascii')),))

        print("[INFO] RSA keys generated and private key encrypted.")
        




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
