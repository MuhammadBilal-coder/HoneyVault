import os
from Crypto.Cipher import AES

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENCRYPTED_DIR = os.path.join(PROJECT_ROOT, "encrypted_files")
DECRYPTED_DIR = os.path.join(PROJECT_ROOT, "decrypted_files")

os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

MAGIC = b"HV1"

def decrypt_file(enc_filename: str, wrap_key: bytes):
    """
    enc_filename: e.g. "myfile.docx.enc" (only name)
    wrap_key: 16 bytes (Shamir comes from combination)
    Return: decrypted file path
    """
    enc_path = os.path.join(ENCRYPTED_DIR, enc_filename)
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    with open(enc_path, "rb") as f:
        header_magic = f.read(3)
        if header_magic != MAGIC:
            raise ValueError("Invalid encrypted file format (bad magic).")

        nonce_file = f.read(12)
        tag_file = f.read(16)

        nonce_key = f.read(12)
        tag_key = f.read(16)
        wrapped_key = f.read(32)

        ciphertext_file = f.read()

    if not isinstance(wrap_key, (bytes, bytearray)) or len(wrap_key) != 16:
        raise ValueError("wrap_key must be 16 bytes (from Shamir).")

    # 1) Unwrap data_key
    cipher_key = AES.new(wrap_key, AES.MODE_GCM, nonce=nonce_key)
    data_key = cipher_key.decrypt_and_verify(wrapped_key, tag_key)  # returns 32 bytes

    # 2) Decrypt file
    cipher_file = AES.new(data_key, AES.MODE_GCM, nonce=nonce_file)
    plaintext = cipher_file.decrypt_and_verify(ciphertext_file, tag_file)

    # output name
    base_name = enc_filename[:-4] if enc_filename.endswith(".enc") else (enc_filename + ".decrypted")
    out_path = os.path.join(DECRYPTED_DIR, base_name)

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path
