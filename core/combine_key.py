from Crypto.Protocol.SecretSharing import Shamir

def combine_shares(share_strings):
    """
    share_strings: ["1-<hex>", "2-<hex>"]  (at least threshold=2)
    return: bytes (16 bytes wrap_key)
    """
    shares = []
    for s in share_strings:
        s = s.strip()
        if "-" not in s:
            raise ValueError("Invalid share format. Expected 'index-hex'.")
        idx_str, hexdata = s.split("-", 1)
        idx = int(idx_str)
        share_bytes = bytes.fromhex(hexdata)
        shares.append((idx, share_bytes))

    # Shamir.combine returns bytes
    return Shamir.combine(shares)
