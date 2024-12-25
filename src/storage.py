import os

def save_hmac(output_dir, hmac_value):
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "hmac.txt"), "w") as f:
        f.write(hmac_value)

def retrieve_data(file_path):
    with open(file_path, "rb") as f:
        return f.read()