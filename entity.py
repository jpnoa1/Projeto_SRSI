from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket
import json
import random
from utils import sk_encryption, pk_encryption
import os

class Entity:
    def __init__(self, PORT):
        self.private_key = None
        self.public_key = None
        self.signed_certificate = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ca_certificate = None
        self.ID = random.randint(1000, 9999)
        self.password = None
        self.contacts = []
        self.session_key = None
        self.contact_signed_cert = None
        self.port = PORT
        

    def create_key_pair(self):
        # Generate RSA keys
        self.password = input("Enter the password to protect the private key: ")
        print("[INFO] Creating a key pair...")
        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        self.public_key = self.private_key.public_key()
        
        if self.private_key is None or self.public_key is None:
            print("[ERROR] Could not generate RSA keys. Exiting...")
            return False
        
        print("[INFO] RSA keys generated.")

        # Store the private key by encrypting it with a password
        with open(f"users/users_privkeys/private_key_{self.ID}.pem", "wb") as f:
            f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.BestAvailableEncryption(self.password.encode('ascii')),))
        
        print("[INFO] RSA keys generated and private key stored.")
        return True
    
    def read_privkey(self):
        with open(f"users/users_privkeys/private_key_{self.ID}.pem", "rb") as f:
            cert = f.read()
        return cert

    def request_certificates(self):
        # Verify and load the private key
        try:
            print("[INFO] Loading private key...")
            with open(f"users/users_privkeys/private_key_{self.ID}.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=self.password.encode('ascii'))
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
        PORT = input("Enter the port to connect to ca: ")
        while not PORT.isdigit():
            print("[ERROR] Invalid port number. Try again.")
        PORT = int(PORT)
        self.socket.connect(("localhost", PORT))
        print("[INFO] Connected to CA.")
        self.port = self.socket.getsockname()[1]
        
    def create_CSR(self):
        print("To create the CSR (Certificate Signing Request) we need to collect some data. Please enter it bellow:")
        while True:
            country_name = input("Country Code (MUST BE EXACTLY 2 CHARACTERS): ")
            common_name = input("Common Name: ")
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
            
            signed_cert = x509.load_pem_x509_certificate(signed_cert_pem)
            ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem)
            
            print("[INFO] Signed certificate and CA certificate received from CA.")
            with open(f"users/users_certs/signed_cert_{self.ID}.pem", "wb") as f:
                f.write(signed_cert_pem)
            with open(f"users/ca_cert_to_user/ca_cert_{self.ID}.pem", "wb") as f:
                f.write(ca_cert_pem)
            return signed_cert, ca_certificate            
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON decode error: {e}")
        except KeyError as e:
            print(f"[ERROR] Missing key in response: {e}")
        except ValueError as e:
            print(f"[ERROR] Invalid certificate format: {e}")
        return None, None
    
    def get_ca_certificate(self):
        with open(f"users/ca_cert_to_user/ca_cert_{self.ID}.pem", "rb") as f:
            cert = f.read()
        return cert
    
    def authenticate_with_contact_sender(self, contact_socket):
        # Send the signed certificate to the contact
        contact_socket.send(self.signed_certificate.public_bytes(serialization.Encoding.PEM))
        
        # Receive the contact's signed certificate
        contact_signed_cert_pem = contact_socket.recv(4096)
        self.contact_signed_cert = x509.load_pem_x509_certificate(contact_signed_cert_pem)
        
        # Load the CA certificate
        ca_cert_pem = self.get_ca_certificate()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        
        # Verify the contact's signed certificate
        try:
            ca_cert.public_key().verify(
                self.contact_signed_cert.signature,
                self.contact_signed_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.contact_signed_cert.signature_hash_algorithm,
            )            
            print("[INFO] Contact's certificate verified.")
        except Exception as e:
            print(f"[ERROR] Could not verify contact's certificate: {e}")
            return False
        
        return True
    
    def authenticate_with_contact_receiver(self, contact_socket, contact_signed_cert_pem):
        # Send the signed certificate to the contact
        contact_socket.send(self.signed_certificate.public_bytes(serialization.Encoding.PEM))
        
        self.contact_signed_cert = x509.load_pem_x509_certificate(contact_signed_cert_pem)
        
        # Load the CA certificate
        ca_cert_pem = self.get_ca_certificate()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        
        # Verify the contact's signed certificate
        try:
            ca_cert.public_key().verify(
                self.contact_signed_cert.signature,
                self.contact_signed_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.contact_signed_cert.signature_hash_algorithm,
            )            
            print("[INFO] Contact's certificate verified.")
        except Exception as e:
            print(f"[ERROR] Could not verify contact's certificate: {e}")
            return False
        
        return True   
    
    def wait_for_connection(self):
        print("[INFO] Waiting for connection...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        
        try:
            while True:
                try:
                    conn, addr = server_socket.accept()
                    print(f"[INFO] Connection established with {addr}")
                    contact_signed_cert_pem = conn.recv(4096)
                    if self.authenticate_with_contact_receiver(conn, contact_signed_cert_pem):
                        print("[INFO] Connection authenticated.")
                        print("[INFO] This entity will create the session key.")
                        self.session_key = os.urandom(32)
                        encrypted_sk = pk_encryption.cipher_with_public_key(self.session_key, self.contact_signed_cert.public_key())
                        conn.send(encrypted_sk)
                        print("[INFO] Session key created and sent.")
                        
                        while True:
                            try:
                                response = conn.recv(4096)
                                if not response:
                                    print("[INFO] The client has closed the connection.")
                                    break
                                decrypted_response = sk_encryption.decrypt_with_sk(response, 'CBC', self.session_key, iv=os.urandom(16), nonce=os.urandom(16))
                                if decrypted_response == b'exit':
                                    print("[INFO] The client has closed the connection.")
                                    break
                                print(f"Response: {decrypted_response.decode('utf-8')}")
                                
                                message = input("Enter the message to send (or type 'exit' to close the connection): ")
                                if message.lower() == 'exit':
                                    print("[INFO] Closing connection.")
                                    break
                                
                                encrypted_message = sk_encryption.encrypt_with_sk(message.encode('utf-8'), 'CBC', self.session_key, iv=os.urandom(16), nonce=os.urandom(16))
                                conn.send(encrypted_message)
                                print("[INFO] Message sent.")
                            except Exception as e:
                                print(f"[ERROR] Error during communication: {e}")
                                
                        self.menu()
                    else:
                        print("[ERROR] Could not authenticate with contact. Exiting connection.")
                        self.menu()
                
                except KeyboardInterrupt:
                    print("[INFO] Shutting down the server.")
                    break
                except Exception as e:
                    print(f"[ERROR] Error accepting connection: {e}")
        finally:
            server_socket.close()
            self.session_key = None
            print("[INFO] Connection closed.")
            self.menu()
        
    def menu(self):
        print("1. Request certificates")
        print("2. Connect and send message to another entity")
        print("3. Exit")
        if self.private_key is not None and self.public_key is not None and self.signed_certificate is not None and self.ca_certificate is not None and self.port is not None:
            print(f"Entity available on port: {self.port} \nWith ID: {self.ID}")
        if self.private_key is not None and self.public_key is not None and self.signed_certificate is not None and self.ca_certificate is not None:
            print("Certificates and keys already exist.")
        else:
            print("No keys or certificates obtained yet.")
        
        option = input("Choose an option: ")
        if option == "1":
            if self.private_key is None or self.public_key is None or self.signed_certificate is None or self.ca_certificate is None:
                if entity.create_key_pair():
                    print("[INFO] Key pair created, now preparing to request certificates...")
                    if entity.request_certificates() is None:
                        print("[ERROR] Could not request certificates. Exiting...")
                        exit(1)
                    else:
                        print("[INFO] Certificates received successfully.")
                        self.socket.close()
                        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
                            self.socket.close()
                            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            self.menu()
        elif option == "2":
            print("1. Connect to contact")
            print("2. Wait for contact connection")
            print("3. Back")
            print(f"Entity available on port: {self.port} \nWith ID: {self.ID}")

            option = input("Choose an option: ")
            if self.private_key is None or self.public_key is None or self.signed_certificate is None or self.ca_certificate is None:
                print("[ERROR] Keys and certificates do not exist. Please request certificates first.")
                self.menu()
            elif option == "1":
                self.connect_and_send_message()
            elif option == "2":
                self.wait_for_connection()
            else:
                self.menu()
        elif option == "3":
            exit(0)
        else:
            print("Invalid option. Try again.")
            self.menu()
            
            
    def contact_exists(self, name):
        for contact in self.contacts:
            if contact['name'] == name:
                return True
        return False
          
    def connect_and_send_message(self):
        port = None
        while port is None or not port.isdigit():
            port = input("Enter the port of the entity you want to connect to: ")
            port_number = int(port)
        
        try:
            self.socket.connect(("localhost", port_number))   
            self.contacts.append({   
                "port": port
            })
        except Exception as e:
            print(f"[ERROR] Could not connect to localhost:{port_number}: {e} \nRestarting...")
            self.connect_and_send_message()
        
        if self.authenticate_with_contact_sender(self.socket):
            print("[INFO] Connection established and authenticated.")
            print("[INFO] Waiting for the server entity to create the session key.")
            encrypted_sk = self.socket.recv(4096)
            self.session_key = pk_encryption.decipher_with_private_key(self.private_key, encrypted_sk)
            print("[INFO] Session key received.")
            
            while True:
                try:
                    message = input("Enter the message to send (or type 'exit' to close the connection): ")
                    
                    if message.lower() == 'exit':
                        print("[INFO] Closing connection, after sending the last message.")
                        encrypted_message = sk_encryption.encrypt_with_sk(message.encode('utf-8'), 'CBC', self.session_key, iv=os.urandom(16), nonce=os.urandom(16))
                        self.socket.send(encrypted_message)
                        print("[INFO] Message sent.")
                        break
                    
                    
                    encrypted_message = sk_encryption.encrypt_with_sk(message.encode('utf-8'), 'CBC', self.session_key, iv=os.urandom(16), nonce=os.urandom(16))
                    self.socket.send(encrypted_message)
                    
                    response = self.socket.recv(4096)
                    if not response:
                        print("[INFO] The server has closed the connection.")
                        break                    
                    
                    decrypted_response = sk_encryption.decrypt_with_sk(response, 'CBC', self.session_key, iv=os.urandom(16), nonce=os.urandom(16))
                    print(f"Response: {decrypted_response.decode('utf-8')}")
                    
                    if decrypted_response == b'exit':
                        print("[INFO] The server has closed the connection.")
                        break
                except KeyboardInterrupt:
                    print("[INFO] Closing connection.")
                    break
                except Exception as e:
                    print(f"[ERROR] An error occurred: {e}")
                    break
                
        else:
            print("[ERROR] Could not authenticate with contact. Exiting connection.")
            self.menu()

        self.socket.close()
        self.session_key = None
        print("[INFO] Connection closed.")
        self.menu()
        
        
        
          
if __name__ == "__main__":
    entity = Entity(9992)
    entity.menu()
            
            
    