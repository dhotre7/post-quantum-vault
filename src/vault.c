#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "../include/vault.h"

int vault_keygen(const char *pk_path, const char *sk_path) {
    const char *kem_name = "ML-KEM-768";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (kem == NULL) return -1;

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        return -1;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        explicit_bzero(secret_key, kem->length_secret_key);
        free(public_key);
        free(secret_key);
        OQS_KEM_free(kem);
        return -1;
    }

    FILE *f_pk = fopen(pk_path, "wb");
    if (f_pk) {
        fwrite(public_key, 1, kem->length_public_key, f_pk);
        fclose(f_pk);
    }

    FILE *f_sk = fopen(sk_path, "wb");
    if (f_sk) {
        fwrite(secret_key, 1, kem->length_secret_key, f_sk);
        fclose(f_sk);
    }

    explicit_bzero(secret_key, kem->length_secret_key);
    free(public_key);
    free(secret_key);
    OQS_KEM_free(kem);

    return (f_pk && f_sk) ? 0 : -1;
}

int vault_seal(const char *pk_path, const char *in_path, const char *out_path) {
    const char *kem_name = "ML-KEM-768";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) return -1;

    FILE *f_pk = fopen(pk_path, "rb");
    if (!f_pk) {
        OQS_KEM_free(kem);
        return -1;
    }
    uint8_t *public_key = malloc(kem->length_public_key);
    if (fread(public_key, 1, kem->length_public_key, f_pk) != kem->length_public_key) {
        free(public_key);
        fclose(f_pk);
        OQS_KEM_free(kem);
        return -1;
    }
    fclose(f_pk);

    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, kem_ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        free(public_key);
        free(kem_ciphertext);
        free(shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }
    free(public_key);

    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        free(kem_ciphertext);
        explicit_bzero(shared_secret, kem->length_shared_secret);
        free(shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || 
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, shared_secret, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ciphertext);
        explicit_bzero(shared_secret, kem->length_shared_secret);
        free(shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }

    FILE *f_in = fopen(in_path, "rb");
    FILE *f_out = fopen(out_path, "wb");
    if (!f_in || !f_out) {
        if (f_in) fclose(f_in);
        if (f_out) fclose(f_out);
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ciphertext);
        explicit_bzero(shared_secret, kem->length_shared_secret);
        free(shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }

    uint32_t magic = VAULT_MAGIC;
    uint8_t version = VAULT_VERSION;
    fwrite(&magic, 1, sizeof(magic), f_out);
    fwrite(&version, 1, sizeof(version), f_out);
    fwrite(kem_ciphertext, 1, kem->length_ciphertext, f_out);
    fwrite(nonce, 1, sizeof(nonce), f_out);

    long tag_pos = ftell(f_out);
    uint8_t placeholder_tag[16] = {0};
    fwrite(placeholder_tag, 1, sizeof(placeholder_tag), f_out);

    fseek(f_in, 0, SEEK_END);
    uint32_t plaintext_len = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    fwrite(&plaintext_len, 1, sizeof(plaintext_len), f_out);

    uint8_t in_buf[4096];
    uint8_t out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    while (!feof(f_in)) {
        size_t bytes_read = fread(in_buf, 1, sizeof(in_buf), f_in);
        if (bytes_read > 0) {
            EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
            fwrite(out_buf, 1, out_len, f_out);
        }
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    if (out_len > 0) {
        fwrite(out_buf, 1, out_len, f_out);
    }

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    fseek(f_out, tag_pos, SEEK_SET);
    fwrite(tag, 1, sizeof(tag), f_out);

    fclose(f_in);
    fclose(f_out);
    EVP_CIPHER_CTX_free(ctx);
    free(kem_ciphertext);
    explicit_bzero(shared_secret, kem->length_shared_secret);
    free(shared_secret);
    OQS_KEM_free(kem);

    return 0;
}

int vault_open(const char *sk_path, const char *in_path, const char *out_path) {
    const char *kem_name = "ML-KEM-768";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) return -1;

    // 1. Open the encrypted vault file
    FILE *f_in = fopen(in_path, "rb");
    if (!f_in) {
        OQS_KEM_free(kem);
        return -1;
    }

    // 2. Read and verify the Magic Header and Version
    uint32_t magic;
    uint8_t version;
    if (fread(&magic, 1, sizeof(magic), f_in) != sizeof(magic) || 
        fread(&version, 1, sizeof(version), f_in) != sizeof(version)) {
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1; // File is too small or broken
    }
    if (magic != VAULT_MAGIC || version != VAULT_VERSION) {
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1; // Not a vault file, or wrong version
    }

    // 3. Read the security puzzle, nonce, tag, and original size
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t nonce[12];
    uint8_t tag[16];
    uint32_t plaintext_len;

    if (fread(kem_ciphertext, 1, kem->length_ciphertext, f_in) != kem->length_ciphertext ||
        fread(nonce, 1, sizeof(nonce), f_in) != sizeof(nonce) ||
        fread(tag, 1, sizeof(tag), f_in) != sizeof(tag) ||
        fread(&plaintext_len, 1, sizeof(plaintext_len), f_in) != sizeof(plaintext_len)) {
        free(kem_ciphertext);
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1;
    }

    // 4. Load the physical Secret Key from disk
    FILE *f_sk = fopen(sk_path, "rb");
    if (!f_sk) {
        free(kem_ciphertext);
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1;
    }
    uint8_t *secret_key = malloc(kem->length_secret_key);
    if (fread(secret_key, 1, kem->length_secret_key, f_sk) != kem->length_secret_key) {
        explicit_bzero(secret_key, kem->length_secret_key);
        free(secret_key);
        free(kem_ciphertext);
        fclose(f_in);
        fclose(f_sk);
        OQS_KEM_free(kem);
        return -1;
    }
    fclose(f_sk);

    // 5. Solve the puzzle to recover the AES password (shared_secret)
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, shared_secret, kem_ciphertext, secret_key) != OQS_SUCCESS) {
        explicit_bzero(secret_key, kem->length_secret_key);
        free(secret_key);
        free(shared_secret);
        free(kem_ciphertext);
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1;
    }
    
    // Destroy the hardware secret key from RAM after solving the puzzle.
    explicit_bzero(secret_key, kem->length_secret_key);
    free(secret_key);
    free(kem_ciphertext); 

    // 6. Setup AES-GCM for Decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, shared_secret, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(shared_secret, kem->length_shared_secret);
        free(shared_secret);
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1;
    }

    // 7. Open the output file to write the decrypted diary
    FILE *f_out = fopen(out_path, "wb");
    if (!f_out) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(shared_secret, kem->length_shared_secret);
        free(shared_secret);
        fclose(f_in);
        OQS_KEM_free(kem);
        return -1;
    }

    // 8. Stream the Decryption
    uint8_t in_buf[4096];
    uint8_t out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    while (!feof(f_in)) {
        size_t bytes_read = fread(in_buf, 1, sizeof(in_buf), f_in);
        if (bytes_read > 0) {
            EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
            fwrite(out_buf, 1, out_len, f_out);
        }
    }

    // 9. CHECK THE TAMPER-PROOF STICKER!
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int decrypt_success = EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    
    if (decrypt_success > 0 && out_len > 0) {
        fwrite(out_buf, 1, out_len, f_out);
    }

    // 10. Memory Cleanup
    fclose(f_in);
    fclose(f_out);
    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(shared_secret, kem->length_shared_secret);
    free(shared_secret);
    OQS_KEM_free(kem);

    if (decrypt_success <= 0) {
        // SCAM ALERT! The sticker was broken or the password was wrong.
        // We MUST delete the output file to protect the user from fake data.
        remove(out_path);
        return -1; 
    }

    return 0;
}
