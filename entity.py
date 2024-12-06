from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import socket

class Entity:
    def __init__(self, HOST, PORT):
        self.private_key = None
        self.file_name = None
        self.public_key = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(HOST, PORT)


    def create_key_pair(self):
        # Generate RSA keys
        input_password = input("Enter the password to protect the private key: ")
        print("Creating a key pair... this may take some time...")
        self.private_key = rsa.generate_key_pair(key_size=2048)
        self.public_key = self.private_key.public_key()

        # Store the private key by encrypting it with a password
        self.file_name = input("Enter the filename to store the private key: ")
        with open(self.file_name, "wb") as f:
            f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.BestAvailableEncryption(input_password.encode('ascii')),))
        
        print("[INFO] RSA keys generated and private key stored.")
        

    def request_certificates(self):
        # Verify and load the private key
        input_password = input("Enter the password to access the private key: ")
        try:
            with open(self.file_name, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=input_password.encode('ascii'))

            print("[INFO] Private key loaded.")
        except Exception as e:
            print("[ERROR] Could not load private key. Exiting...")
            return
        
        # Connect to the CA
        self.connect_to_CA()
        
        # Create a certificate signing request
        csr = self.create_CSR()
        
        # Send the CSR and receive the signed certificate and the CA certificate
        signed_certificate, ca_certificate = self.send_CSR_and_receive_certificates(csr)
        return signed_certificate, ca_certificate
    
    def connect_to_CA(self):
        self.socket.connect("Server_Address", "Server_Port")
        print("[INFO] Connected to CA.")
        
    def create_CSR(self):
        print("To create the CSR we need to collect some data. Please enter it bellow:")
        country_name = input("Country Name: ")
        state_or_province_name = input("State or Province Name: ")
        locality_name = input("Locality Name: ")
        organization_name = input("Organization Name: ")
        common_name = input("Common Name: ")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Details to be contained in the certificate
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Alternative names for common name
                x509.DNSName(u"mysite.com"),
                x509.DNSName(u"www.mysite.com"),
            ]),
            critical=False,
        # Sign the CSR with our private key
        ).sign(self.private_key, hashes.SHA256())
        return csr


    def send_CSR_and_receive_certificates(self, csr):
        self.socket.connect("Server_Address", "Server_Port")
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        self.socket.send(csr_pem)

        signed_cert_pem, ca_certificate = self.socket.recv(4096)
        signed_cert = x509.load_pem_x509_certificate(signed_cert_pem)
        print("[INFO] Signed certificate received from CA.")
        return signed_cert, ca_certificate


if __name__ == "__main__":
    HOST = "localhost"
    PORT = 8080
    entity = Entity(HOST, PORT)
    entity.create_key_pair()
    entity.request_certificates()
    