import logging
import datetime
from typing import AsyncIterator

import grpc
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from envoy.service.secret.v3 import sds_pb2, sds_pb2_grpc
from envoy.extensions.transport_sockets.tls.v3 import tls_pb2
from google.protobuf import any_pb2

logger = logging.getLogger(__name__)

class SecretDiscoveryHandler(sds_pb2_grpc.SecretDiscoveryServiceServicer):
    """
    SDS server implementation for on-demand dynamic certificate generation.
    """

    def __init__(self, ca_cert_path: str, ca_key_path: str):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._load_ca()

    def _load_ca(self):
        try:
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.info(f"Loaded Intermediate CA: {self.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        except Exception as e:
            logger.error(f"Failed to load CA: {e}")
            raise

    def _generate_cert(self, common_name: str):
        """Generates a site-specific certificate signed by the Intermediate CA."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # SAN (Subject Alternative Name) is required for modern browsers/tools
        alt_names = [x509.DNSName(common_name)]
        if common_name.startswith("*."):
            pass # Wildcard handling if needed
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )

        certificate = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
        )

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        # Also need the chain (Intermediate CA)
        chain_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
        
        return cert_pem, key_pem, chain_pem

    async def FetchSecrets(self, request, context):
        raise NotImplementedError("Use StreamSecrets for SDS")

    async def StreamSecrets(
        self,
        request_iterator: AsyncIterator[sds_pb2.DiscoveryRequest],
        context: grpc.ServicerContext,
    ) -> AsyncIterator[sds_pb2.DiscoveryResponse]:
        
        async for request in request_iterator:
            resource_names = request.resource_names
            logger.info(f"Received SDS request for: {resource_names}")
            
            resources = []
            for name in resource_names:
                # If name starts with "sds_cert:", treat as SNI request
                # Note: Envoy's on_demand SDS often uses the SNI as the secret name.
                sni = name
                try:
                    cert_pem, key_pem, chain_pem = self._generate_cert(sni)
                    
                    secret = sds_pb2.Secret(
                        name=name,
                        tls_certificate=tls_pb2.TlsCertificate(
                            certificate_chain=tls_pb2.DataSource(
                                inline_bytes=cert_pem + chain_pem
                            ),
                            private_key=tls_pb2.DataSource(
                                inline_bytes=key_pem
                            )
                        )
                    )
                    
                    any_secret = any_pb2.Any()
                    any_secret.Pack(secret)
                    resources.append(any_secret)
                    logger.info(f"Generated dynamic cert for {sni}")
                    
                except Exception as e:
                    logger.error(f"Error generating cert for {sni}: {e}")

            yield sds_pb2.DiscoveryResponse(
                version_info="1",
                resources=resources,
                type_url="type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
                nonce=request.response_nonce
            )

    async def DeltaSecrets(self, request_iterator, context):
        raise NotImplementedError("Delta SDS not implemented")
