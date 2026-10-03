import pytest
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.pki.csr import parse_and_validate_csr, CSRError
from app.pki.policy import CertKind, BOOTSTRAP_EKU_OID
from app.pki.ca import CAEngine
from app.pki.crl import generate_crl

def generate_test_csr(curve=ec.SECP256R1()) -> str:
    key = ec.generate_private_key(curve)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

def test_csr_validation_success():
    csr_pem = generate_test_csr()
    csr, pub_key = parse_and_validate_csr(csr_pem)
    assert csr is not None
    assert isinstance(pub_key, ec.EllipticCurvePublicKey)

def test_csr_validation_rejects_secp384r1():
    csr_pem = generate_test_csr(ec.SECP384R1())
    with pytest.raises(CSRError, match="P-256"):
        parse_and_validate_csr(csr_pem)

def test_ca_engine_issuance():
    ca = CAEngine(
        key_path="./secrets/intermediate.key",
        cert_path="./pki-state/intermediate.crt",
        chain_path="./pki-state/ca-chain.pem"
    )
    csr_pem = generate_test_csr()
    
    # Issue Operational Cert
    cert, cert_pem, serial_hex = ca.issue_certificate(
        csr_pem=csr_pem,
        entity_id="dev-test-01",
        role_name="sensor",
        lifetime_seconds=604800,
        kind=CertKind.OPERATIONAL
    )
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "dev-test-01"
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "sensor"
    eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value

    # Issue Bootstrap Cert
    boot_cert, _, _ = ca.issue_certificate(
        csr_pem=csr_pem,
        entity_id="dev-test-01",
        role_name="sensor",
        lifetime_seconds=604800,
        kind=CertKind.BOOTSTRAP
    )
    boot_eku = boot_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert BOOTSTRAP_EKU_OID in boot_eku.value
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in boot_eku.value

def test_crl_generation(tmp_path):
    ca = CAEngine(
        key_path="./secrets/intermediate.key",
        cert_path="./pki-state/intermediate.crt",
        chain_path="./pki-state/ca-chain.pem"
    )
    out_crl = tmp_path / "crl.pem"
    crl_bytes = generate_crl(ca, [(12345, datetime.now(timezone.utc))], crl_number=1, output_path=str(out_crl))
    assert out_crl.exists()
    crl = x509.load_pem_x509_crl(crl_bytes)
    assert crl.issuer == ca.intermediate_cert.subject
