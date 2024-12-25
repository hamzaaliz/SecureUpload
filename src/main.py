# Importing all the necessary libraries
import os
from encrypt import encrypt_dataset, save_encrypted_data, generate_rsa_keypair
from decrypt import decrypt_dataset
from verify import generate_hmac, verify_hmac
from storage import save_hmac, retrieve_data

def main():
    # These are absolute paths to the dataset, keys and output directory
    dataset_path = "/Users/HamzaAli/Desktop/InfoSec_Project/data/oldbookings-daywise.csv"
    public_key_path = "/Users/HamzaAli/Desktop/InfoSec_Project/keys/public.pem"
    private_key_path = "/Users/HamzaAli/Desktop/InfoSec_Project/keys/private.pem"
    output_dir = "/Users/HamzaAli/Desktop/InfoSec_Project/output"

    # Generate an RSA Key Pair
    private_key, public_key = generate_rsa_keypair()
    #os.makedirs("keys", exist_ok=True)
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)

    # Encrypt the Dataset
    ciphertext, tag, enc_session_key, nonce = encrypt_dataset(dataset_path, public_key_path)
    save_encrypted_data(output_dir, ciphertext, tag, enc_session_key, nonce)

    # Decrypt the Dataset
    decrypted_data = decrypt_dataset(
        enc_session_key_path=f"{output_dir}/rsa_session_key.bin",
        nonce_path=f"{output_dir}/nonce.bin",
        tag_path=f"{output_dir}/tag.bin",
        ciphertext_path=f"{output_dir}/encrypted_data.bin",
        private_key_path=private_key_path,
    )

    # Save the Decrypted Dataset for Verification
    decrypted_dataset_path = f"{output_dir}/decrypted_dataset.csv"
    with open(decrypted_dataset_path, "wb") as f:
        f.write(decrypted_data)
    print(f"Decrypted dataset saved to {decrypted_dataset_path}")

    # Generate and Save HMAC
    secret_key = os.urandom(16)
    hmac_value = generate_hmac(ciphertext, secret_key)
    save_hmac(output_dir, hmac_value)

    # Verification Demonstration
    print("Verifying HMAC...")
    stored_hmac = retrieve_data(os.path.join(output_dir, "hmac.txt")).decode()
    verification_result = verify_hmac(ciphertext, stored_hmac, secret_key)
    if verification_result:
        print("HMAC Verified: Integrity Maintained.")
    else:
        print("HMAC Verification Failed: Data Tampered!")

if __name__ == "__main__":
    main()