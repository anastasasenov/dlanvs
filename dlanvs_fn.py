# DLANVS

import argparse
import base64
import cmd
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import queue
import secrets
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from cls.voting_engine import VotingEngine
from cls.store_db import Database
from cls.crypto_manager import CryptoManager
from cls.transport_net import Network


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_ts() -> float:
    return utc_now().timestamp()


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha256(canonical(obj))


def safe_uuid() -> str:
    return str(uuid.uuid4())


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_public_key_bytes(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def participant_id_from_cert(cert: x509.Certificate) -> str:
    return sha256(cert_public_key_bytes(cert))


def certificate_name(cert: x509.Certificate) -> str:
    try:
        vals = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return vals[0].value if vals else "unknown"
    except Exception:
        return "unknown"


def load_cert(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_private_key(path: str, password: Optional[str] = None):
    data = Path(path).read_bytes()
    pwd = password.encode() if password else None
    return serialization.load_pem_private_key(data, password=pwd)


def save_pem(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)


def sign(private_key, data: bytes) -> bytes:
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("This implementation expects Ed25519 private keys")
    return private_key.sign(data)


def verify(cert: x509.Certificate, signature: bytes, data: bytes) -> bool:
    try:
        cert.public_key().verify(signature, data)
        return True
    except Exception:
        return False


def verify_cert_signed_by(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        if cert.issuer != ca.subject:
            return False
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        # Ed25519 certificates have no signature_hash_algorithm.
        try:
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        except Exception:
            return False


def valid_certificate(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    now = utc_now()
    try:
        # cryptography versions differ in these properties; support both.
        nbf = getattr(cert, "not_valid_before_utc", None)
        naf = getattr(cert, "not_valid_after_utc", None)
        if nbf is None:
            nbf = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        if naf is None:
            naf = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
        return (
            nbf <= now <= naf
            and cert.subject != ca.subject
            and verify_cert_signed_by(cert, ca)
        )
    except Exception:
        return False
    
def generate_ca(out_cert: str, out_key: str, common_name="DLANVS Root CA"):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    save_pem(out_key, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    save_pem(out_cert, cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created CA certificate: {out_cert}")
    print(f"Created CA private key:    {out_key}")


def generate_node(name: str, ca_cert_path: str, ca_key_path: str,
                  out_cert: str, out_key: str):
    ca_cert = load_cert(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, None)
    )
    save_pem(out_key, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    save_pem(out_cert, cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created node certificate: {out_cert}")
    print(f"Created node private key: {out_key}")


def ensure_group_key(path: str):
    p = Path(path)
    if not p.exists():
        p.write_text(b64e(secrets.token_bytes(32)))
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        print(f"Created group key: {path}")

def run_gui(engine: VotingEngine, network: Network):
    print("TODO")
