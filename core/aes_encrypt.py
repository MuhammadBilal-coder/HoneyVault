import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

UPLOAD_DIR = os.path.join(PROJECT_ROOT, "uploads")
ENCRYPTED_DIR = os.path.join(PROJECT_ROOT, "encrypted_files")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

MAGIC = b"HV1"  # header marker

def encrypt_file(filename: str):
  
    input_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Upload file not found: {input_path}")

    # actual file encryption key (AES-256)
    data_key = get_random_bytes(32)

    wrap_key = get_random_bytes(16)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # 1) Encrypt FILE with data_key (GCM)
    nonce_file = get_random_bytes(12)
    cipher_file = AES.new(data_key, AES.MODE_GCM, nonce=nonce_file)
    ciphertext_file, tag_file = cipher_file.encrypt_and_digest(plaintext)

  
    nonce_key = get_random_bytes(12)
    cipher_key = AES.new(wrap_key, AES.MODE_GCM, nonce=nonce_key)
    wrapped_key, tag_key = cipher_key.encrypt_and_digest(data_key)  # 32 bytes in, 32 bytes out

    # Save output
    output_path = os.path.join(ENCRYPTED_DIR, filename + ".enc")

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(nonce_file)
        f.write(tag_file)
        f.write(nonce_key)
        f.write(tag_key)
        f.write(wrapped_key)
        f.write(ciphertext_file)

    return output_path, wrap_key
