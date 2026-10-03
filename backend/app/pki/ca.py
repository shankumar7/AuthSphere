"""
AuthSphere Certificate Authority (CA) Engine
Handles loading intermediate CA credentials and issuing end-entity certificates from validated CSRs.
"""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import settings
from app.pki.csr import parse_and_validate_csr
from app.pki.policy import CertKind, get_certificate_eku, build_entity_san

class CAEngine:
    def __init__(self, key_path: str | None = None, cert_path: str | None = None, chain_path: str | None = None):
        root_dir = Path(__file__).resolve().parent.parent.parent.parent
        
        default_key = root_dir / "secrets" / "intermediate.key"
        default_cert = root_dir / "pki-state" / "intermediate.crt"
        default_chain = root_dir / "pki-state" / "ca-chain.pem"

        self.key_path = Path(key_path) if key_path and Path(key_path).exists() else default_key
        self.cert_path = Path(cert_path) if cert_path and Path(cert_path).exists() else default_cert
        self.chain_path = Path(chain_path) if chain_path and Path(chain_path).exists() else default_chain

        self.intermediate_key = self._load_private_key()
        self.intermediate_cert = self._load_cert(self.cert_path)
        self.ca_chain_pem = self._load_chain_pem()


    def _load_private_key(self) -> ec.EllipticCurvePrivateKey:
        data = self.key_path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Intermediate CA key must be EC P-256")
        return key

    def _load_cert(self, path: Path) -> x509.Certificate:
        return x509.load_pem_x509_certificate(path.read_bytes())


    def _load_chain_pem(self) -> str:
        if self.chain_path.exists():
            return self.chain_path.read_text()
        return self.intermediate_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def issue_certificate(
        self,
        csr_pem: str,
        entity_id: str,
        role_name: str,
        lifetime_seconds: int,
        kind: CertKind = CertKind.OPERATIONAL
    ) -> Tuple[x509.Certificate, str, str]:
        """
        Validates CSR, ignores client CSR subject/extensions, and builds fresh certificate.
        Returns (certificate_obj, cert_pem_string, serial_hex_string).
        """
        csr, pub_key = parse_and_validate_csr(csr_pem)

        ou_value = "bootstrap" if kind == CertKind.BOOTSTRAP else role_name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou_value),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
        ])

        now = datetime.now(timezone.utc)
        not_before = now - timedelta(seconds=60)
        not_after = now + timedelta(seconds=lifetime_seconds)
        
        serial_int = x509.random_serial_number()
        serial_hex = f"{serial_int:032x}"

        ski = x509.SubjectKeyIdentifier.from_public_key(pub_key)
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key())
        ekus = get_certificate_eku(kind)
        san = build_entity_san(entity_id)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.intermediate_cert.subject)
            .public_key(pub_key)
            .serial_number(serial_int)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage(ekus), critical=True)
            .add_extension(san, critical=False)
            .add_extension(ski, critical=False)
            .add_extension(aki, critical=False)
        )

        cert = builder.sign(self.intermediate_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        return cert, cert_pem, serial_hex
