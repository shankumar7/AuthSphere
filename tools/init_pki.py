#!/usr/bin/env python3
"""
tools/init_pki.py — AuthSphere PKI Initialization Script

Generates:
1. Offline Root CA key pair & self-signed certificate (P-256, 10 years).
2. Online Intermediate CA key pair & certificate signed by Root CA (P-256, 2 years).
3. Broker server certificate & key signed by Intermediate CA (P-256, 90 days).
4. Service certificates (svc-api, svc-bridge) signed by Intermediate CA (P-256, 365 days).
5. Initial empty CRL signed by Intermediate CA.
6. Copies firmware root CA slot (root_current.pem) and generates random secret files.
"""
import os
import sys
import argparse
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())

def save_key_pem(key: ec.EllipticCurvePrivateKey, path: Path, password: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)
    path.chmod(0o400)

def save_cert_pem(cert: x509.Certificate, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem)

def build_root_ca(root_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "AuthSphere Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
    ])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(ski, critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return cert

def build_intermediate_ca(
    inter_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    root_key: ec.EllipticCurvePrivateKey
) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "AuthSphere Intermediate CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
    ])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return cert

def build_broker_cert(
    broker_key: ec.EllipticCurvePrivateKey,
    inter_cert: x509.Certificate,
    inter_key: ec.EllipticCurvePrivateKey,
    mqtt_host: str,
    hostname: str
) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, mqtt_host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
    ])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(broker_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key())

    import ipaddress
    san_list = [x509.DNSName("mosquitto"), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for h in [mqtt_host, hostname]:
        try:
            ip = ipaddress.ip_address(h)
            if x509.IPAddress(ip) not in san_list:
                san_list.append(x509.IPAddress(ip))
        except ValueError:
            if x509.DNSName(h) not in san_list:
                san_list.append(x509.DNSName(h))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(inter_cert.subject)
        .public_key(broker_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(inter_key, hashes.SHA256())
    )
    return cert

def build_service_cert(
    cn: str,
    svc_key: ec.EllipticCurvePrivateKey,
    inter_cert: x509.Certificate,
    inter_key: ec.EllipticCurvePrivateKey
) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "service"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthSphere"),
    ])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(svc_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key())

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(inter_cert.subject)
        .public_key(svc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(inter_key, hashes.SHA256())
    )
    return cert

def build_initial_crl(
    inter_cert: x509.Certificate,
    inter_key: ec.EllipticCurvePrivateKey
) -> x509.CertificateRevocationList:
    now = datetime.now(timezone.utc)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(inter_cert.subject)
        .last_update(now - timedelta(seconds=60))
        .next_update(now + timedelta(days=7))
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(inter_key, hashes.SHA256())
    )
    return crl

def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize AuthSphere PKI Infrastructure")
    parser.add_argument("--out-offline", default="./pki-offline", help="Path for offline root keys")
    parser.add_argument("--out-state", default="./pki-state", help="Path for public PKI state")
    parser.add_argument("--out-secrets", default="./secrets", help="Path for secret key files")
    parser.add_argument("--mqtt-host", default="localhost", help="MQTT Public Hostname")
    parser.add_argument("--hostname", default="localhost", help="Public Hostname")
    args = parser.parse_args()

    out_offline = Path(args.out_offline)
    out_state = Path(args.out_state)
    out_secrets = Path(args.out_secrets)

    print("[*] Generating AuthSphere Root CA...")
    root_key = generate_ec_key()
    root_cert = build_root_ca(root_key)
    save_key_pem(root_key, out_offline / "root.key")
    save_cert_pem(root_cert, out_offline / "root.crt")

    print("[*] Generating AuthSphere Intermediate CA...")
    inter_key = generate_ec_key()
    inter_cert = build_intermediate_ca(inter_key, root_cert, root_key)
    save_key_pem(inter_key, out_secrets / "intermediate.key")
    save_cert_pem(inter_cert, out_state / "intermediate.crt")

    # Combine intermediate + root into ca-chain.pem
    chain_pem = (
        inter_cert.public_bytes(serialization.Encoding.PEM) +
        root_cert.public_bytes(serialization.Encoding.PEM)
    )
    (out_state / "ca-chain.pem").write_bytes(chain_pem)

    print("[*] Generating Broker Server Certificate...")
    broker_key = generate_ec_key()
    broker_cert = build_broker_cert(broker_key, inter_cert, inter_key, args.mqtt_host, args.hostname)
    save_key_pem(broker_key, out_state / "broker.key")
    save_cert_pem(broker_cert, out_state / "broker.crt")

    print("[*] Generating Service Certificates (svc-api, svc-bridge)...")
    svc_api_key = generate_ec_key()
    svc_api_cert = build_service_cert("svc-api", svc_api_key, inter_cert, inter_key)
    save_key_pem(svc_api_key, out_secrets / "svc_api.key")
    save_cert_pem(svc_api_cert, out_state / "svc_api.crt")

    svc_bridge_key = generate_ec_key()
    svc_bridge_cert = build_service_cert("svc-bridge", svc_bridge_key, inter_cert, inter_key)
    save_key_pem(svc_bridge_key, out_secrets / "svc_bridge.key")
    save_cert_pem(svc_bridge_cert, out_state / "svc_bridge.crt")

    print("[*] Generating Initial CRL...")
    crl = build_initial_crl(inter_cert, inter_key)
    (out_state / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    print("[*] Generating firmware Root CA slot (firmware/esp32/certs/root_current.pem)...")
    fw_certs_dir = Path("firmware/esp32/certs")
    fw_certs_dir.mkdir(parents=True, exist_ok=True)
    save_cert_pem(root_cert, fw_certs_dir / "root_current.pem")

    print("[*] Generating application secret files...")
    out_secrets.mkdir(parents=True, exist_ok=True)
    (out_secrets / "jwt_secret.txt").write_text(secrets.token_urlsafe(32) + "\n")
    (out_secrets / "fernet_key.txt").write_text(secrets.token_urlsafe(32) + "\n")
    (out_secrets / "postgres_password.txt").write_text(secrets.token_urlsafe(16) + "\n")
    (out_secrets / "dynsec_admin_password.txt").write_text(secrets.token_urlsafe(16) + "\n")

    print("[+] AuthSphere PKI Initialized Successfully!")

if __name__ == "__main__":
    main()
