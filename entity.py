from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import socket
import json

class Entity:
    def __init__(self):
        self.private_key = None
        self.file_name = None
        self.public_key = None
        self.signed_certificate = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ca_certificate = None
        # self.contacts = []


    def create_key_pair(self):
        # Generate RSA keys
        input_password = input("Enter the password to protect the private key: ")
        print("[INFO] Creating a key pair...")
        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        self.public_key = self.private_key.public_key()
        
        if self.private_key is None or self.public_key is None:
            print("[ERROR] Could not generate RSA keys. Exiting...")
            return False
        
        print("[INFO] RSA keys generated.")

        # Store the private key by encrypting it with a password
        self.file_name = input("Enter the filename to store the private key: ")
        with open(f"keys/{self.file_name}.pem", "wb") as f:
            f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.BestAvailableEncryption(input_password.encode('ascii')),))
        
        print("[INFO] RSA keys generated and private key stored.")
        return True
    
    def read_crt(self):
        with open(self.file_name, "rb") as f:
            cert = f.read()
        return cert

    def request_certificates(self):
        # Verify and load the private key
        input_password = input("Enter the password to access the private key: ")
        try:
            
            print("[INFO] Loading private key...")
            with open(self.file_name, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=input_password.encode('ascii'))
            print("[INFO] Private key loaded.")
            
        except Exception as e:
            print("[ERROR] Could not load private key. Exiting...")
                    
        # Connect to the CA
        print("[INFO] Connecting to CA...")
        self.connect_to_CA()
        
        # Create a certificate signing request
        csr = self.create_CSR()
        
        # Send the CSR and receive the signed certificate and the CA certificate
        self.signed_certificate, self.ca_certificate = self.send_CSR_and_receive_certificates(csr)
        return self.signed_certificate, self.ca_certificate
    
    def connect_to_CA(self):
        HOST = "localhost"
        PORT = input("Enter the port to connect to ca: ")
        while not PORT.isdigit():
            print("[ERROR] Invalid port number. Try again.")
        PORT = int(PORT)
        self.socket.connect(("localhost", PORT))
        print("[INFO] Connected to CA.")
        
    def create_CSR(self):
        print("To create the CSR (Certificate Signing Request) we need to collect some data. Please enter it bellow:")
        while True:
            country_name = input("Country Code (MUST BE EXACTLY 2 CHARACTERS): ")
            if len(country_name) == 2:
                break
            print("[ERROR] Country Code must be exactly 2 characters. Please try again.")
        state_or_province_name = input("State or Province Name: ")
        locality_name = input("Locality Name: ")
        organization_name = input("Organization Name: ")
        common_name = input("Common Name: ")
        
        # Create a certificate signing request
        print("[INFO] Creating a Certificate Signing Request...")
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
        print("[INFO] CSR created.")
        
        return csr

    def send_CSR_and_receive_certificates(self, csr):
        # Send the CSR to the CA
        print("[INFO] Sending the CSR to the CA...")
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        self.socket.send(csr_pem)
        
        # Receive the signed certificate and the CA certificate
        data = self.socket.recv(4096)
        try:
            response = json.loads(data.decode('utf-8'))
            signed_cert_pem = response['signed_cert_pem'].encode('utf-8')
            ca_cert_pem = response['ca_cert_pem'].encode('utf-8')
            
            print(signed_cert_pem.decode('utf-8'))
            print("\n")
            print(ca_cert_pem.decode('utf-8'))
            
            signed_cert = x509.load_pem_x509_certificate(signed_cert_pem)
            ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem)
            print("[INFO] Signed certificate and CA certificate received from CA.")
            return signed_cert, ca_certificate            
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON decode error: {e}")
        except KeyError as e:
            print(f"[ERROR] Missing key in response: {e}")
        except ValueError as e:
            print(f"[ERROR] Invalid certificate format: {e}")
        return None, None
    
    def menu(self):
        print("1. Request certificates")
        print("2. Connect and send message to another entity")
        print("3. Exit")
        option = input("Choose an option: ")
        if option == "1":
            if self.private_key is None or self.public_key is None or self.file_name is None or self.signed_certificate is None or self.ca_certificate is None:
                if entity.create_key_pair():
                    print("[INFO] Key pair created, now preparing to request certificates...")
                    if entity.request_certificates() is None:
                        print("[ERROR] Could not request certificates. Exiting...")
                        exit(1)
                    else:
                        print("[INFO] Certificates received successfully.")
                        self.menu()
            else:
                option2 = input("Keys and certificates alreay exists, do you want to overwrite them? (y/n): ")
                if option2.lower() == 'y':
                    if entity.create_key_pair():
                        print("[INFO] Key pair created, now preparing to request certificates...")
                        if entity.request_certificates() is None:
                            print("[ERROR] Could not request certificates. Exiting...")
                            exit(1)
                        else:
                            print("[INFO] Certificates received successfully.")
                            self.menu()
        elif option == "2":
            if self.private_key is None or self.public_key is None or self.file_name is None or self.signed_certificate is None or self.ca_certificate is None:
                print("[ERROR] Keys and certificates do not exist. Please request certificates first.")
                self.menu()
            else:
                self.connect_and_send_message()
        elif option == "3":
            exit(0)
        else:
            print("Invalid option. Try again.")
            self.menu()
            
    def connect_and_send_message(self):
        print("Enter the IP address of the entity you want to connect to: ")
        ip = input("IP: ")
        print("Enter the port of the entity you want to connect to: ")
        port = input("Port: ")
        print("Enter the name of the entity you want to connect to: ")
        name = input("Name: ")
        print("[INFO] Storing contact and connecting to entity...")
        
        print("[INFO] Connecting to entity...")
        self.socket.connect((ip, port))
        
        # self.contacts.append({
        #     "name": name,
        #     "ip": ip,
        #     "port": port
        # })
        
        try:
            while True:
                message = input("Enter the message you want to send (or type 'exit' to close the connection): ")
                if message.lower() == 'exit':
                    print("[INFO] Closing connection.")
                    break

                self.socket.send(message.encode('utf-8'))
                response = self.socket.recv(4096)
                if not response:
                    print("[INFO] The server has closed the connection.")
                    break

                print(f"Response: {response.decode('utf-8')}")
        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        finally:
            self.socket.close()
            print("[INFO] Connection closed.")
          

if __name__ == "__main__":
    entity = Entity()
    entity.menu()
            
            
    