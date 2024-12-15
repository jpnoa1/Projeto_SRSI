from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta
import json
import threading

class Gateway:
    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT
        self.public_key = None
        self.password = None
        self.assigned_certificates = 0
        
    def generate_keys(self):
        # Generate RSA keys
        self.password = input("Enter the password to protect the private key: ")
        print("[INFO] Creating key pair")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = private_key.public_key()
        print("[INFO] RSA keys generated.")
        
        # Store the private key by encrypting it with a password
        with open("certificate_authority/gateway_key.pem", "wb") as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(self.password.encode('ascii')),))

        print("[INFO] RSA keys generated and stored the private key encrypted")
        if private_key is None or self.public_key is None:
            print("[ERROR] Could not generate RSA keys. Exiting...")
            return False
        return True
    
    def read_crt(self):
        with open("certificate_authority/root_certificate.pem", "rb") as f:
            cert = f.read()
        return cert
    
    def read_prvkey(self):
        try:
            with open("certificate_authority/gateway_key.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=self.password.encode('ascii'))
            if self.private_key:
                print("[INFO] Private key loaded successfully.")
                return self.private_key
        except Exception as e:
            print(f"[ERROR] Could not load private key: {e}, restarting CA...")
            main()
 
            
    def create_self_signed_certificate(self, privkey):
        print("Creating a self-signed certificate...")
        print("To do this we need to collect some data. Please enter it bellow:")
        while True:
            country_name = input("Country Code (MUST BE EXACTLY 2 CHARACTERS): ")
            if len(country_name) == 2:
                break
            print("[ERROR] Country Code must be exactly 2 characters. Please try again.")
            
        state_or_province_name = input("State or Province Name: ")
        locality_name = input("Locality Name: ")
        organization_name = input("Organization Name: ")
        common_name = input("Common: ")
        
        print("[INFO] Creating self signed certificate")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
             datetime.now(timezone.utc)
        ).not_valid_after(
            # 10 years in duration
           datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True
        # Sign the certificate
        ).sign(privkey, hashes.SHA256())
        # write certificate to disk
        print("[INFO] Self Signed Certificate created now storing it")
        
        with open("certificate_authority/root_certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print("[INFO] Self Signed Certificate stored")
        
        if certificate is None:
            print("[ERROR] Could not create self signed certificate. Exiting...")
            return False
        return True
        
    def load_csr_and_issue_certificate(self, csr, cert, privkey):
        
        print("[INFO] Loading CSR and validating signature")
        x509_csr = x509.load_pem_x509_csr(csr)
        if x509_csr.is_signature_valid:
            print("CSR signature is valid!!!")
            with open(f"certificate_authority/user_csrs/user_csr_{self.assigned_certificates}.pem", "wb") as f:
                f.write(x509_csr.public_bytes(serialization.Encoding.PEM))
        else:
            print("CSR signature is invalid!!!")
            return False
        
        print("[INFO] Loading CA certificate")
        x509_ca_cert = x509.load_pem_x509_certificate(cert)
        s_cn = x509_csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        s_st = x509_csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
        s_ln = x509_csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
        s_on = x509_csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        s_c = x509_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        s_publickey = x509_csr.public_key()

        i_cn = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        i_st = x509_ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
        i_ln = x509_ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
        i_on = x509_ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        i_c = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            
        # print("CSR information")
        # print("Country Name: " + s_cn)
        # print("State or Province Name: " + s_st)
        # print("Locality Name: " + s_ln)
        # print("Organization Name: " + s_on)
        # print("Common Name: " + s_c)
        
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, s_cn),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s_st),
            x509.NameAttribute(NameOID.LOCALITY_NAME, s_ln),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, s_on),
            x509.NameAttribute(NameOID.COMMON_NAME, s_c),
        ])

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, i_cn),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, i_st),
            x509.NameAttribute(NameOID.LOCALITY_NAME, i_ln),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, i_on),
            x509.NameAttribute(NameOID.COMMON_NAME, i_c),
        ])
        
        print("[INFO] Creating and signing the certificate")
        user_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            s_publickey
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
             datetime.now(timezone.utc)
        ).not_valid_after(
            # 10 years in duration
           datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False,
                        content_commitment=False, data_encipherment=True, key_agreement=True, encipher_only=False,
                        decipher_only=False),
            critical=True
            # Sign the certificate
        ).sign(privkey, hashes.SHA256())
        print("[INFO] Certificate created and signed")
        
        print("[INFO] Storing the certificate")
        with open(f"certificate_authority/user_certs/user_cert_{self.assigned_certificates}.pem", "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))
            # f.write("\n\n")
        self.assigned_certificates += 1
        print("[INFO] Certificate stored")
        
        return user_cert
    
    def handle_client(self, client_socket):
        try:
            csr = client_socket.recv(4096)
            ca_cert_pem = self.read_crt().decode('utf-8')
            signed_cert_pem = self.load_csr_and_issue_certificate(csr, self.read_crt(), self.read_prvkey()).public_bytes(serialization.Encoding.PEM).decode('utf-8')    
            response = json.dumps({
                'signed_cert_pem': signed_cert_pem,
                'ca_cert_pem': ca_cert_pem
            })
            client_socket.send(response.encode('utf-8'))
            print("Certificado enviado para o cliente  ")
        except Exception as e:
            print(f"[ERROR] Error handling client: {e}")
        finally:
            client_socket.close()
            
            
def main():
    # Inicializar a entidade Gateway
    HOST = "localhost"
    PORT = input("Enter the port to connect to: ")
    while not PORT.isdigit():
        print("[ERROR] Invalid port number. Try again.")
        PORT = input("Enter the port to connect to: ")
    PORT_NUMBER = int(PORT)
    gateway = Gateway(HOST, PORT_NUMBER)
    print("[*] Inicializing Gateway...")
    if gateway.generate_keys():
        print("[INFO] Keys generated")
        privkey = gateway.read_prvkey()
        if gateway.create_self_signed_certificate(privkey):
            print("[INFO] Self Signed Certificate created, CA initialized")
    else:
        print("[ERROR] Could not generate keys. r...")
        choice = input("Would you like to try again (y) or exit (e)? (y/e): ")
        if choice == "y":
            main()
        else:
            return
    
    # Configurar o socket do Gateway
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT_NUMBER))
    server.listen(5)
    
    print(f"[*] Gateway listening on port {PORT_NUMBER}...")

    try:
        while True:
            try:
                # Accept connections (blocking call)
                client_socket, client_address = server.accept()
                print(f"Conexction recerived from: {client_address}")
                client_handler = threading.Thread(target=gateway.handle_client, args=(client_socket,))
                client_handler.start()
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                print("[INFO] Shutting down the gateway.")
                break
    except KeyboardInterrupt:
        print("[INFO] Shutting down the gateway.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
