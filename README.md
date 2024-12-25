## **SecureUpload: Ensuring Confidentiality and Integrity**

### **Project Overview**

SecureUpload is a Python-based security mechanism designed to ensure the **confidentiality** and **integrity** of datasets.

This project includes functionalities to:

- Encrypt datasets using AES (for confidentiality).
- Decrypt datasets securely using RSA (asymmetric encryption for session key management).
- Generate and verify HMACs to detect data tampering (for integrity).
- Simulate attacks to demonstrate system vulnerabilities and compromises.

### **Features**

1. **Confidentiality**:
   - AES encryption ensures data is only accessible to authorized parties.
   - RSA encryption secures the AES session key.
2. **Integrity**:
   - HMACs verify that the dataset remains unaltered during storage or transmission.
3. **Attack Simulation**:
   - Demonstrates system compromises by decrypting data and tampering with records.

### **Usage**

#### **Setup**

1. Clone the repository and navigate to the project directory.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

#### **Run Demonstrations**

1. **Showcase Confidentiality and Integrity:**

   ```bash
   python src/main.py
   ```

   - Encrypts a dataset and verifies its integrity using HMAC.
   - Decrypts the dataset to ensure proper recovery.

2. **Simulate Attacks:**
   ```bash
   python src/attack.py
   ```
   - Demonstrates compromised confidentiality by successfully decrypting and displaying dataset records.
   - Shows compromised integrity by tampering with the dataset (removing columns/rows).

### **Dependencies**

- Python 3.8+
- Pandas
- PyCryptodome

### **Output Files**

- Encrypted data: `output/encrypted_data.bin`
- Decrypted data: `output/decrypted_dataset.csv`
- Tampered data (after attack): `output/decrypted_dataset.csv`
