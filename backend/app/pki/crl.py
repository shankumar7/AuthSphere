"""
CRL Generator for AuthSphere PKI
Generates signed X.509 CRL from revoked certificates list and writes atomically to /pki-state/crl.pem.
"""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.pki.ca import CAEngine

def generate_crl(
    ca_engine: CAEngine,
    revoked_items: Sequence[tuple[int, datetime]],  # list of (serial_int, revoked_at_dt)
    crl_number: int,
    output_path: str = "./pki-state/crl.pem"
) -> bytes:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_engine.intermediate_cert.subject)
        .last_update(now - timedelta(seconds=60))
        .next_update(now + timedelta(days=7))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )

    for serial_int, revoked_at in revoked_items:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_engine.intermediate_key, hashes.SHA256())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    # Atomic write to output path
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(dir=out_file.parent, prefix="crl_", suffix=".tmp")
    try:
        with os.fdopen(temp_fd, "wb") as f:
            f.write(crl_pem)
        os.replace(temp_path, out_file)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    return crl_pem
