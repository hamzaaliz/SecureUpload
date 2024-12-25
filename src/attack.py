from Crypto.PublicKey import RSA
from decrypt import decrypt_dataset
from storage import retrieve_data
import pandas as pd
import os
import random
from io import BytesIO

def confidentiality_attack():
    print("\n[Confidentiality Attack]")
    try:
        # Use the valid RSA private key to decrypt the dataset
        decrypted_data = decrypt_dataset(
            enc_session_key_path="output/rsa_session_key.bin",
            nonce_path="output/nonce.bin",
            tag_path="output/tag.bin",
            ciphertext_path="output/encrypted_data.bin",
            private_key_path="keys/private.pem",
        )

        # Load decrypted data into a Pandas DataFrame
        df = pd.read_csv(BytesIO(decrypted_data))
        print("Confidentiality Compromised: DataFrame Loaded")
        print(df.head())
        
    except Exception as e:
        print(f"Confidentiality Attack Failed. Error: {e}")

def integrity_attack():
    print("\n[Integrity Attack]")
    try:
        # Use the decrypted dataset to simulate tampering
        decrypted_data = decrypt_dataset(
            enc_session_key_path="output/rsa_session_key.bin",
            nonce_path="output/nonce.bin",
            tag_path="output/tag.bin",
            ciphertext_path="output/encrypted_data.bin",
            private_key_path="keys/private.pem",
        )

        # Load the decrypted data into a DataFrame
        df = pd.read_csv(BytesIO(decrypted_data))

        # Simulate tampering by dropping 50% of the columns
        columns_to_drop = random.sample(list(df.columns), len(df.columns) // 2)
        df = df.drop(columns=columns_to_drop)

        # Simulate tampering by removing random rows
        rows_to_remove = random.sample(range(len(df)), len(df) // 3)
        df = df.drop(rows_to_remove)

        # Save the tampered dataset
        tampered_output_path = "output/decrypted_dataset.csv"
        df.to_csv(tampered_output_path, index=False)
        print(f"Tampered dataset saved to {tampered_output_path}")
        print("Integrity Compromised: DataFrame Tampered")
        print(df.head())
    except Exception as e:
        print(f"Integrity Attack Failed. Error: {e}")

def main():
    confidentiality_attack()
    integrity_attack()

if __name__ == "__main__":
    main()