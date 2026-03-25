# 🔒 Post-Quantum Vault (C CLI)

A hybrid quantum-safe command-line file encryption tool. Built in C using `liboqs` (ML-KEM-768) and `OpenSSL` (AES-256-GCM).

## 🛡️ Why Post-Quantum? (Harvest-Now, Decrypt-Later)
Current public-key encryption (like RSA) is vulnerable to future quantum computers running Shor’s algorithm. Attackers are currently harvesting encrypted network traffic knowing they can decrypt it in 10-15 years. 
This tool provides **Harvest-Now-Decrypt-Later** protection by wrapping an AES-256 symmetric key using **ML-KEM-768**, a NIST-standardized quantum-resistant algorithm.

## ⚙️ Architecture (The Hybrid Pipeline)
1. **Key Encapsulation:** `ML-KEM-768` creates a math puzzle (KEM Ciphertext) and a 256-bit solution (`shared_secret`).
2. **Symmetric Encryption:** A 12-byte random non-reusable nonce is generated. `AES-256-GCM` uses the nonce and the `shared_secret` to violently scramble your file at high speeds.
3. **Authentication:** AES-GCM tags the file with a 16-byte Tamper-Proof Auth Tag. If a single bit is flipped by malware in transit, the vault securely refuses to unlock it.

## 🚀 Building & Usage

### 1. Dependencies
You need OpenSSL dev headers and `liboqs` installed system-wide:
```bash
sudo apt update && sudo apt install libssl-dev cmake build-essential
git clone -b 0.15.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON .. && make -j$(nproc) && sudo make install
```

### 2. Compilation
```bash
make vault
```

### 3. Usage
```bash
# 1. Generate Post-Quantum Keys (Creates mykey.pk & mykey.sk)
./vault keygen --out mykey


#### 4. Personal Message
   Guys it took so much effort from my side i took this project because when i first read about it in a reddit post it quickly grabbed my attention and i reasearched about it and thought of making this project also for  many part of code i took help from ai and also thank you to MIT for letting me use their ML-Kem algorithm for this project . thank you


# 2. Encrypt a File
./vault seal --key mykey.pk secret_document.pdf

# 3. Decrypt the Vault File
./vault open --key mykey.sk secret_document.pdf.vault
```
