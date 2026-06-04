
def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack consecutive bits into bytes, MSB first within each byte."""
    if len(bits) < 256:
        raise ValueError(
            "Need at least 256 bits (32 bytes of key material) to XOR with an AES-256 key."
        )
    usable = len(bits) - (len(bits) % 8)
    out: list[int] = []
    for i in range(0, usable, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | (bits[i + j] & 1)
        out.append(byte_val)
    return bytes(out)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Return the bitwise XOR of two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("Byte strings must have the same length for XOR.")
    return bytes([x ^ y for x, y in zip(a, b)])
