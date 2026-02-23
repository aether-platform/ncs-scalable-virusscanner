import os
import unittest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Mock paths - will be created during test
CA_CERT_PATH = "/tmp/test_ca.crt"
CA_KEY_PATH = "/tmp/test_ca.key"

from aether_platform.virusscan.producer.interfaces.grpc.sds import SecretDiscoveryHandler

class TestSDSGeneration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # 1. Create a dummy Intermediate CA for testing
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test-intermediate-ca"),
        ])
        cls.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            cls.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(cls.ca_key, hashes.SHA256())

        with open(CA_CERT_PATH, "wb") as f:
            f.write(cls.ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(CA_KEY_PATH, "wb") as f:
            f.write(cls.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(CA_CERT_PATH):
            os.remove(CA_CERT_PATH)
        if os.path.exists(CA_KEY_PATH):
            os.remove(CA_KEY_PATH)

    def test_cert_generation(self):
        handler = SecretDiscoveryHandler(CA_CERT_PATH, CA_KEY_PATH)
        target_domain = "www.google.com"
        
        cert_pem, key_pem, chain_pem = handler._generate_cert(target_domain)
        
        # Verify cert_pem
        cert = x509.load_pem_x509_certificate(cert_pem)
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, target_domain)
        
        # Verify Issuer (must match our test CA)
        self.assertEqual(cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "test-intermediate-ca")
        
        # Verify SAN
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertIn(target_domain, [name.value for name in san.value])
        
        # Verify Private Key
        key = serialization.load_pem_private_key(key_pem, password=None)
        self.assertIsInstance(key, rsa.RSAPrivateKey)

if __name__ == "__main__":
    unittest.main()
