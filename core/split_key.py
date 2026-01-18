from Crypto.Protocol.SecretSharing import Shamir

def split_key(key: bytes, parts: int = 3, threshold: int = 2):
    """
    AES breaks key by Shamir into shares me .
    returns: list of strings, e.g. '1-abcd...'
    """
    shares = Shamir.split(threshold, parts, key)
    result = []
    for idx, share_bytes in shares:
        # string format: "index-hexdata"
        result.append(f"{idx}-{share_bytes.hex()}")
    return result
