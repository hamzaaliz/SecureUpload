import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_dataset(dataset_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    with open(dataset_path, "rb") as f:
        data = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return ciphertext, tag, enc_session_key, cipher_aes.nonce

def save_encrypted_data(output_dir, ciphertext, tag, enc_session_key, nonce):
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "encrypted_data.bin"), "wb") as f:
        f.write(ciphertext)
    with open(os.path.join(output_dir, "rsa_session_key.bin"), "wb") as f:
        f.write(enc_session_key)
    with open(os.path.join(output_dir, "nonce.bin"), "wb") as f:
        f.write(nonce)
    with open(os.path.join(output_dir, "tag.bin"), "wb") as f:
        f.write(tag)