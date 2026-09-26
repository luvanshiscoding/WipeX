"""
WipeX - workstation signing key.
ECDSA P-256 (secp256r1) signatures over SHA-256 for certificates and audit entries.
The key pair is generated on first use and kept in <data dir>/keys (never committed).
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

import paths

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CryptoSigner:
    """Workstation ECDSA P-256 signer (certificates, audit log)."""

    _KEY_DIR = os.environ.get("WIPEX_KEYS") or os.path.join(paths.data_dir(), "keys")
    _PRIVATE_KEY_PATH = os.path.join(_KEY_DIR, "signer_private.pem")
    _PUBLIC_KEY_PATH = os.path.join(_KEY_DIR, "signer_public.pem")
    _private_key = None
    _public_key = None

    @classmethod
    def _init_keys(cls):
        """Initializes or loads persistent NIST P-256 ECDSA key pair."""
        if cls._private_key is not None:
            return

        os.makedirs(cls._KEY_DIR, exist_ok=True)

        if HAS_CRYPTOGRAPHY:
            if os.path.exists(cls._PRIVATE_KEY_PATH) and os.path.exists(cls._PUBLIC_KEY_PATH):
                try:
                    with open(cls._PRIVATE_KEY_PATH, "rb") as f:
                        cls._private_key = serialization.load_pem_private_key(f.read(), password=None)
                    with open(cls._PUBLIC_KEY_PATH, "rb") as f:
                        cls._public_key = serialization.load_pem_public_key(f.read())
                    return
                except Exception:
                    pass

            # Generate new NIST P-256 key pair
            cls._private_key = ec.generate_private_key(ec.SECP256R1())
            cls._public_key = cls._private_key.public_key()

            # Save PEMs
            pem_priv = cls._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pem_pub = cls._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(cls._PRIVATE_KEY_PATH, "wb") as f:
                f.write(pem_priv)
            with open(cls._PUBLIC_KEY_PATH, "wb") as f:
                f.write(pem_pub)

    @classmethod
    def get_public_key_pem(cls) -> str:
        """Workstation public key (PEM); empty when the cryptography library is missing."""
        cls._init_keys()
        if HAS_CRYPTOGRAPHY and cls._public_key is not None:
            pem = cls._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode("utf-8")
        return ""

    @staticmethod
    def generate_nonce() -> str:
        """Generates a 128-bit cryptographically secure hexadecimal nonce."""
        return secrets.token_hex(16)

    @staticmethod
    def generate_sha256(canonical_payload: str) -> str:
        """Computes SHA-256 digest of hardware parameters and wipe telemetry."""
        return hashlib.sha256(canonical_payload.encode('utf-8')).hexdigest()

    @classmethod
    def sign_payload(cls, canonical_payload: str) -> str:
        """
        Signs the canonical string using NIST P-256 ECDSA.
        Returns Base64-encoded ASN.1 DER signature.
        """
        cls._init_keys()
        if HAS_CRYPTOGRAPHY and cls._private_key is not None:
            try:
                sig_bytes = cls._private_key.sign(
                    canonical_payload.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                )
                return base64.b64encode(sig_bytes).decode('utf-8')
            except Exception:
                pass

        # No signing key available: return an explicit unsigned marker (never verifies)
        return "UNSIGNED"

    @classmethod
    def verify_signature(cls, canonical_payload: str, signature_b64: str, public_key_pem: Optional[str] = None) -> bool:
        """
        Verifies an ECDSA digital signature against the canonical payload.
        Fails closed: without the cryptography library nothing can be verified.
        """
        if not HAS_CRYPTOGRAPHY:
            return False

        cls._init_keys()
        try:
            pub = cls._public_key
            if public_key_pem:
                pub = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

            if not pub:
                return False

            sig_bytes = base64.b64decode(signature_b64)
            pub.verify(
                sig_bytes,
                canonical_payload.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, Exception):
            return False
