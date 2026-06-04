from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def encrypt_aesgcm(text:str, key:bytes):
    if len(key)!=32:
        raise ValueError('Key must be 32 bytes for AES 256')
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    return {
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce
    }

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    if len(key)!=32:
        raise ValueError('Key must be 32 bytes for AES 256')
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    text = cipher.decrypt_and_verify(ciphertext, tag)

    return text.decode()

def encrypt_session_key(session_key: bytes, public_key_pem: bytes):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher.encrypt(session_key)
    return encrypted_key

def decrypt_session_key(encrypted_key: bytes, private_key_pem: bytes):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    session_key = cipher.decrypt(encrypted_key)
    return session_key