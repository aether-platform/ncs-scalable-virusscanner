import datetime
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import AsyncIterator, NamedTuple

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from envoy.config.core.v3 import base_pb2
from envoy.extensions.transport_sockets.tls.v3 import common_pb2, secret_pb2
from envoy.service.discovery.v3 import discovery_pb2
from envoy.service.secret.v3 import sds_pb2_grpc
from google.protobuf import any_pb2

from aether_platform.virusscan.producer.metrics import SDS_CERTS_GENERATED, SDS_ERRORS

logger = logging.getLogger(__name__)

# Default: cache up to 1000 certs, each valid for 1 hour
_DEFAULT_CACHE_MAX_SIZE = int(os.environ.get("SDS_CACHE_MAX_SIZE", "1000"))
_DEFAULT_CACHE_TTL_SECONDS = int(os.environ.get("SDS_CACHE_TTL_SECONDS", "3600"))


class _CachedCert(NamedTuple):
    cert_pem: bytes
    key_pem: bytes
    chain_pem: bytes
    created_at: float


class SecretDiscoveryHandler(sds_pb2_grpc.SecretDiscoveryServiceServicer):
    """
    SDS server implementation for on-demand dynamic certificate generation.
    Includes an LRU cache to avoid redundant RSA key generation.
    """

    def __init__(
        self,
        ca_cert_path: str,
        ca_key_path: str,
        cache_max_size: int = _DEFAULT_CACHE_MAX_SIZE,
        cache_ttl_seconds: int = _DEFAULT_CACHE_TTL_SECONDS,
    ):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._cache: OrderedDict[str, _CachedCert] = OrderedDict()
        self._cache_max_size = cache_max_size
        self._cache_ttl = cache_ttl_seconds
        self._cache_lock = threading.Lock()
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

    def _get_cached_cert(self, common_name: str) -> _CachedCert | None:
        """Retrieve a cached cert if it exists and hasn't expired."""
        with self._cache_lock:
            entry = self._cache.get(common_name)
            if entry is None:
                return None
            if (time.monotonic() - entry.created_at) > self._cache_ttl:
                del self._cache[common_name]
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(common_name)
            return entry

    def _put_cached_cert(self, common_name: str, entry: _CachedCert):
        """Store a cert in the cache, evicting LRU entries if at capacity."""
        with self._cache_lock:
            if common_name in self._cache:
                self._cache.move_to_end(common_name)
                self._cache[common_name] = entry
            else:
                self._cache[common_name] = entry
                while len(self._cache) > self._cache_max_size:
                    self._cache.popitem(last=False)

    def _generate_cert(self, common_name: str) -> tuple[bytes, bytes, bytes]:
        """Generates a site-specific certificate signed by the Intermediate CA, with caching."""
        cached = self._get_cached_cert(common_name)
        if cached is not None:
            return cached.cert_pem, cached.key_pem, cached.chain_pem

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # SAN (Subject Alternative Name) is required for modern browsers/tools
        alt_names = [x509.DNSName(common_name)]

        now = datetime.datetime.now(datetime.timezone.utc)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now - datetime.timedelta(minutes=5))
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
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

        self._put_cached_cert(
            common_name,
            _CachedCert(cert_pem, key_pem, chain_pem, time.monotonic()),
        )

        return cert_pem, key_pem, chain_pem

    async def FetchSecrets(self, request, context):
        raise NotImplementedError("Use StreamSecrets for SDS")

    async def StreamSecrets(
        self,
        request_iterator: AsyncIterator[discovery_pb2.DiscoveryRequest],
        context: grpc.ServicerContext,
    ) -> AsyncIterator[discovery_pb2.DiscoveryResponse]:

        async for request in request_iterator:
            resource_names = request.resource_names
            logger.info(f"StreamSDS request for: {resource_names}")

            resources = []
            for name in resource_names:
                try:
                    resource = self._build_tls_certificate_secret(name)
                    any_secret = resource.resource
                    resources.append(any_secret)
                    SDS_CERTS_GENERATED.inc()
                    logger.info(f"StreamSDS: generated cert for {name}")
                except Exception as e:
                    SDS_ERRORS.inc()
                    logger.error(f"StreamSDS: error generating cert for {name}: {e}")

            yield discovery_pb2.DiscoveryResponse(
                version_info="1",
                resources=resources,
                type_url="type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
                nonce=request.response_nonce,
            )

    def _build_tls_certificate_secret(self, name: str) -> discovery_pb2.Resource:
        """Build a Resource wrapping a TLS certificate Secret for the given name (SNI)."""
        cert_pem, key_pem, chain_pem = self._generate_cert(name)

        secret = secret_pb2.Secret(
            name=name,
            tls_certificate=common_pb2.TlsCertificate(
                certificate_chain=base_pb2.DataSource(
                    inline_bytes=cert_pem + chain_pem
                ),
                private_key=base_pb2.DataSource(
                    inline_bytes=key_pem
                ),
            ),
        )

        any_secret = any_pb2.Any()
        any_secret.Pack(secret)

        return discovery_pb2.Resource(
            name=name,
            version=uuid.uuid4().hex[:8],
            resource=any_secret,
        )

    async def DeltaSecrets(
        self,
        request_iterator: AsyncIterator[discovery_pb2.DeltaDiscoveryRequest],
        context: grpc.ServicerContext,
    ) -> AsyncIterator[discovery_pb2.DeltaDiscoveryResponse]:
        """
        Delta SDS for on_demand_secret certificate selector.
        Envoy sends resource_names_subscribe with SNI hostnames.
        We generate a certificate per hostname and return as DeltaDiscoveryResponse.
        """
        async for request in request_iterator:
            subscribe = list(request.resource_names_subscribe)
            unsubscribe = list(request.resource_names_unsubscribe)

            if subscribe:
                logger.info(f"DeltaSDS subscribe: {subscribe}")
            if unsubscribe:
                logger.debug(f"DeltaSDS unsubscribe: {unsubscribe}")

            resources = []
            for name in subscribe:
                try:
                    resource = self._build_tls_certificate_secret(name)
                    resources.append(resource)
                    SDS_CERTS_GENERATED.inc()
                    logger.info(f"DeltaSDS: generated cert for {name}")
                except Exception as e:
                    SDS_ERRORS.inc()
                    logger.error(f"DeltaSDS: error generating cert for {name}: {e}")

            yield discovery_pb2.DeltaDiscoveryResponse(
                system_version_info="1",
                resources=resources,
                type_url="type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
                nonce=uuid.uuid4().hex[:8],
                removed_resources=unsubscribe,
            )
