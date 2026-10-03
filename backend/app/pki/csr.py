"""
CSR Validation module for AuthSphere PKI
Enforces EC P-256 (secp256r1) key type and self-signature verification.
"""
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class CSRError(Exception):
    pass

def parse_and_validate_csr(csr_pem: str) -> tuple[x509.CertificateSigningRequest, ec.EllipticCurvePublicKey]:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except Exception as e:
        raise CSRError(f"Invalid CSR PEM format: {e}") from e

    # Verify self-signature
    if not csr.is_signature_valid:
        raise CSRError("CSR signature is invalid")

    pub_key = csr.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise CSRError("CSR public key must be Elliptic Curve (EC)")

    if not isinstance(pub_key.curve, ec.SECP256R1):
        raise CSRError(f"CSR public key curve must be secp256r1 (P-256), got {pub_key.curve.name}")

    return csr, pub_key
