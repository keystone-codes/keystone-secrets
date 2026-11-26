"""Key derivation and AES-256-GCM sealing for secret values.

Derived from stdio-box src/stdio_box/store/crypto.py (Apache-2.0). Modified:
HKDF info labels, SecretUnreadable import, record_id in AAD (ref key).
"""

import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from keystone_secrets.protocol import KeyTooShort, SecretUnreadable

INFO_VALUES = "keystone-secrets/values/v1"
INFO_KEY_CHECK = "keystone-secrets/key-check/v1"
INFO_FORM_CSRF = "keystone-secrets/form-csrf/v1"
INFO_AUDIT_SUB = "keystone-secrets/audit-sub/v1"

_KEY_CHECK_MESSAGE = b"keystone-secrets key check"
_NONCE_BYTES = 12
_DERIVED_BYTES = 32
_MIN_KEY_BYTES = 32


def check_master_key(key: str) -> None:
    if len(key.encode("utf-8")) < _MIN_KEY_BYTES:
        raise KeyTooShort("master key must be at least 32 UTF-8 bytes")


def derive(store_key: str, salt: bytes, info: str) -> bytes:
    """HKDF-SHA256, 32 bytes. Different `info` values yield different keys."""
    return HKDF(
        algorithm=SHA256(),
        length=_DERIVED_BYTES,
        salt=salt,
        info=info.encode("utf-8"),
    ).derive(store_key.encode("utf-8"))


def seal(key: bytes, record_id: str, version: int, values: dict) -> tuple[bytes, bytes]:
    """Encrypt `values`. The nonce is 12 random bytes. AAD binds id and version."""
    nonce = os.urandom(_NONCE_BYTES)
    aad = _aad(record_id, version)
    plaintext = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def open_(key: bytes, record_id: str, version: int, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt a secret row. A wrong key, nonce, or AAD raises SecretUnreadable."""
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(record_id, version))
    except InvalidTag as exc:
        raise SecretUnreadable from exc
    loaded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise SecretUnreadable
    return loaded


def key_check(store_key: str, salt: bytes) -> str:
    """Hex HMAC-SHA256 of the key-check subkey over the fixed label."""
    subkey = derive(store_key, salt, INFO_KEY_CHECK)
    return hmac.new(subkey, _KEY_CHECK_MESSAGE, hashlib.sha256).hexdigest()


def key_id(check_hex: str) -> str:
    """First 8 characters of a key_check hex digest."""
    return check_hex[:8]


def sub_hash(audit_key: bytes, sub: str) -> str:
    """First 16 hex characters of HMAC-SHA256(audit subkey, sub)."""
    return hmac.new(audit_key, sub.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _aad(record_id: str, version: int) -> bytes:
    return f"{record_id}|{version}".encode("utf-8")
