from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_dataset(enc_session_key_path, nonce_path, tag_path, ciphertext_path, private_key_path):
    # Load RSA Private Key
    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    # Load Encrypted AES Session Key
    with open(enc_session_key_path, "rb") as f:
        enc_session_key = f.read()

    # Decrypt AES Session Key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Load Nonce and Tag
    with open(nonce_path, "rb") as f:
        nonce = f.read()
    with open(tag_path, "rb") as f:
        tag = f.read()

    # Load Ciphertext
    with open(ciphertext_path, "rb") as f:
        ciphertext = f.read()

    # Decrypt the Dataset
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_data