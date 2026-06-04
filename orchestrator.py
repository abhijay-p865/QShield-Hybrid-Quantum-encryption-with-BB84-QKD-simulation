import base64
from pathlib import Path
BASE_DIR = Path(__file__).parent
import random
from Crypto.Random import get_random_bytes

from crypto_functions import (
    decrypt_aes_gcm,
    decrypt_session_key,
    encrypt_aesgcm,
    encrypt_session_key,
)
from qkd_sim import simulate_bb84
from utils import bits_to_bytes, xor_bytes


def hybrid_encrypt(plaintext: str, eve_present: bool = False) -> dict:
    """Combine BB84 with RSA-wrapped key material and AES-GCM-encrypt the plaintext."""
    qkd_result = simulate_bb84(num_photons=5000, eve_present=eve_present)
    if not qkd_result["channel_clean"]:
        raise RuntimeError("QKD channel compromised: eavesdropping detected")

    public_key_pem = (BASE_DIR / "receiver.pem").read_bytes()
    session_key = get_random_bytes(32)

    raw_qkd = qkd_result["alice_final_key"]  # already bytes from privacy_amplify
    if len(raw_qkd) >= 32:
        qkd_32 = raw_qkd[:32]
    else:
        qkd_32 = raw_qkd + b"\x00" * (32 - len(raw_qkd))

    hybrid_key = xor_bytes(session_key, qkd_32)
    aes_bundle = encrypt_aesgcm(plaintext, session_key)
    encrypted_hybrid = encrypt_session_key(hybrid_key, public_key_pem)

    return {
        "encrypted_key": base64.b64encode(encrypted_hybrid).decode("utf-8"),
        "ciphertext": base64.b64encode(aes_bundle["ciphertext"]).decode("utf-8"),
        "nonce": base64.b64encode(aes_bundle["nonce"]).decode("utf-8"),
        "tag": base64.b64encode(aes_bundle["tag"]).decode("utf-8"),
        "qber": float(qkd_result["qber"]),
        "sifted_bits": int(qkd_result["sifted_bits"]),
        "channel_clean": bool(qkd_result["channel_clean"]),
        "key_id": "hybrid-rsa2048-bb84-v1",
        "qkd_key": qkd_result["alice_final_key"],
    }


def hybrid_decrypt(
    encrypted_key: str, ciphertext: str, nonce: str, tag: str, qkd_key: bytes
) -> str:
    """Unwrap the hybrid key and decrypt the AES-GCM ciphertext."""
    private_key_pem = (BASE_DIR / "private.pem").read_bytes()
    encrypted_hybrid = base64.b64decode(encrypted_key.encode("utf-8"))
    ciphertext_bytes = base64.b64decode(ciphertext.encode("utf-8"))
    nonce_bytes = base64.b64decode(nonce.encode("utf-8"))
    tag_bytes = base64.b64decode(tag.encode("utf-8"))

    hybrid_key = decrypt_session_key(encrypted_hybrid, private_key_pem)

    raw_qkd = qkd_key  # already bytes, decoded from base64 by the caller
    if len(raw_qkd) >= 32:
        qkd_32 = raw_qkd[:32]
    else:
        qkd_32 = raw_qkd + b"\x00" * (32 - len(raw_qkd))

    session_key = xor_bytes(hybrid_key, qkd_32)
    try:
        return decrypt_aes_gcm(ciphertext_bytes, session_key, nonce_bytes, tag_bytes)
    except ValueError:
        raise ValueError(
            "Decryption failed: message may have been tampered with"
        ) from None


if __name__ == "__main__":
    try:
        enc = hybrid_encrypt("hello quantum world", eve_present=random.choice([True, False]))
        print("qber:", enc["qber"])
        print("channel_clean:", enc["channel_clean"])
        import base64 as _b64
        qkd_key_b64 = _b64.b64encode(enc["qkd_key"]).decode("utf-8")
        plain = hybrid_decrypt(
            enc["encrypted_key"],
            enc["ciphertext"],
            enc["nonce"],
            enc["tag"],
            _b64.b64decode(qkd_key_b64),
        )
        print("recovered:", plain)
    except RuntimeError as exc:
        print(exc)
