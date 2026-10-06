# DLANVS

import secrets
import dataclasses
from typing import Any, Optional
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
import dlanvs_fn as fn

class CryptoManager:
    def __init__(self, cert_path: str, key_path: str, ca_path: str,
                 key_password: Optional[str], group_key_path: str):
        self.cert = fn.load_cert(cert_path)
        self.private_key = fn.load_private_key(key_path, key_password)
        self.ca = fn.load_cert(ca_path)
        self.participant_id = fn.participant_id_from_cert(self.cert)
        self.display_name = fn.certificate_name(self.cert)
        if not fn.valid_certificate(self.cert, self.ca):
            raise ValueError("Node certificate is not valid or not signed by trusted CA")

        if group_key_path:
            p = Path(group_key_path)
            if p.exists():
                raw = fn.b64d(p.read_text().strip())
            else:
                raw = secrets.token_bytes(32)
                p.write_text(fn.b64e(raw))
                try:
                    os.chmod(p, 0o600)
                except Exception:
                    pass
            if len(raw) != 32:
                raise ValueError("Group key must be exactly 32 bytes")
            self.group_key = raw
        else:
            raise ValueError("A group key file is required")

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self.group_key).encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return AESGCM(self.group_key).decrypt(nonce, ciphertext, aad)

    def certificate_b64(self) -> str:
        return fn.b64e(self.cert.public_bytes(serialization.Encoding.DER))

    def make_signature(self, body: dict[str, Any]) -> str:
        return fn.b64e(fn.sign(self.private_key, fn.canonical(body)))

    def verify_event_signature(self, cert: x509.Certificate,
                               event: dict[str, Any]) -> bool:
        sig = fn.b64d(event["signature"])
        unsigned = dict(event)
        unsigned.pop("signature", None)
        return fn.verify(cert, sig, fn.canonical(unsigned))


@dataclasses.dataclass
class Participant:
    participant_id: str
    name: str
    certificate_der: bytes
    last_seen: float
    sequence: int
    status: str = "UNKNOWN"

    @property
    def certificate(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(self.certificate_der)
