"""
Certificate Policy Computation Module for AuthSphere
Computes lifetimes, subject attributes, and extensions based on entity type & kind.
"""
from enum import Enum
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

# Custom OID for Bootstrap certificates (lacks clientAuth so Mosquitto rejects for MQTT)
BOOTSTRAP_EKU_OID = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

class CertKind(str, Enum):
    BOOTSTRAP = "bootstrap"
    OPERATIONAL = "operational"

def get_certificate_eku(kind: CertKind) -> list[ObjectIdentifier]:
    if kind == CertKind.BOOTSTRAP:
        return [BOOTSTRAP_EKU_OID]
    return [ExtendedKeyUsageOID.CLIENT_AUTH]

def build_entity_san(entity_id: str) -> x509.SubjectAlternativeName:
    uri = f"urn:authsphere:entity:{entity_id}"
    return x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)])
