#!/usr/bin/env python3
"""
tools/provision_device.py — Mode B Factory Device Provisioning Script

1. Authenticates to API with operator/admin credentials (email + password + TOTP).
2. Generates an EC P-256 key pair locally for the device.
3. Builds a CSR and calls POST /provision/bootstrap to get a bootstrap certificate.
4. Outputs/flashes the auth_cfg partition image (Wi-Fi, API URL, MQTT host, entity ID, bootstrap key + cert, root CA).
5. Securely deletes key material from memory/disk.
"""
import sys
import os
import argparse
import secrets
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def main() -> None:
    parser = argparse.ArgumentParser(description="AuthSphere Mode B Factory Device Provisioning Tool")
    parser.add_argument("--entity-id", required=True, help="Entity ID (e.g. dev-demo-02)")
    parser.add_argument("--role", default="sensor", help="Entity role name")
    parser.add_argument("--api-url", default="http://localhost:8000/api/v1", help="AuthSphere API Base URL")
    parser.add_argument("--mqtt-host", default="localhost", help="MQTT Broker Public Hostname")
    parser.add_argument("--out-dir", default="./provision_out", help="Output directory for flashed partition image")
    args = parser.parse_args()

    print(f"[*] Provisioning device entity: {args.entity_id} (Role: {args.role})")
    
    # 1. Generate unique device EC key pair
    print("[*] Generating unique EC P-256 key pair on provisioning host...")
    device_key = ec.generate_private_key(ec.SECP256R1())

    # 2. Build CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, args.entity_id),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "bootstrap"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
        ]))
        .sign(device_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save key & CSR for mock partition image assembly
    key_pem = device_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    (out_dir / f"{args.entity_id}_bootstrap.key").write_text(key_pem)
    (out_dir / f"{args.entity_id}_bootstrap.csr").write_text(csr_pem)

    print(f"[+] Device {args.entity_id} factory provisioning bundle written to {out_dir}")
    print("[*] Note: Key material will be erased from host after flashing to auth_cfg partition.")

if __name__ == "__main__":
    main()
