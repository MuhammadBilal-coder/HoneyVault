import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Master key file path (auto-created if missing)
MASTER_KEY_PATH = os.path.join(PROJECT_ROOT, "master_share.key")

MAGIC_PREFIX = "HVSH1:"  # HoneyVault Share Header v1


def _load_or_create_master_key() -> bytes:
    """
    Loads a 32-byte master key from MASTER_KEY_PATH.
    If it doesn't exist, creates it once (random 32 bytes).
    """
    if os.path.exists(MASTER_KEY_PATH):
        with open(MASTER_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("master_share.key invalid length (expected 32 bytes).")
        return key

    # create new master key
    key = get_random_bytes(32)
    with open(MASTER_KEY_PATH, "wb") as f:
        f.write(key)
    return key


def encrypt_share_text(plain_text: str) -> str:
    """
    Encrypts a share string using AES-256-GCM with master key.
    Returns a text string that looks like: 'HVSH1:<base64(...)>'
    """
    key = _load_or_create_master_key()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))

    blob = nonce + tag + ciphertext  # nonce(12) + tag(16) + ct(n)
    b64 = base64.b64encode(blob).decode("utf-8")
    return MAGIC_PREFIX + b64


def decrypt_share_text_if_needed(text: str) -> str:
    """
    If text is encrypted (starts with MAGIC_PREFIX), decrypt it.
    If not, return it as-is (legacy plaintext support).
    """
    if not isinstance(text, str):
        raise TypeError("Share content must be str")

    if not text.startswith(MAGIC_PREFIX):
        # legacy plaintext
        return text.strip()

    key = _load_or_create_master_key()
    b64 = text[len(MAGIC_PREFIX):].strip()

    try:
        blob = base64.b64decode(b64)
    except Exception as e:
        raise ValueError("Invalid encrypted share (base64 decode failed).") from e

    if len(blob) < (12 + 16 + 1):
        raise ValueError("Invalid encrypted share (too short).")

    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plain = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError("Share decryption failed (wrong key or corrupted data).") from e

    return plain.decode("utf-8").strip()
