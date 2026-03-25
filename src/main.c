#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../include/vault.h"

void print_usage() {
    printf("POST-QUANTUM VAULT (v1.0)\n\n");
    printf("Usage:\n");
    printf("  ./vault keygen --out <name>\n");
    printf("      Generates <name>.pk and <name>.sk\n");
    printf("  ./vault seal --key <key.pk> <input_file>\n");
    printf("      Encrypts <input_file> into <input_file>.vault\n");
    printf("  ./vault open --key <key.sk> <vault_file>\n");
    printf("      Decrypts <vault_file> into its original form\n");
}

int file_exists(const char *path) {
    struct stat buffer;   
    return (stat(path, &buffer) == 0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 4 || strcmp(argv[2], "--out") != 0) {
            fprintf(stderr, "[-] Error: Invalid format.\nUsage: ./vault keygen --out <name>\n");
            return 1;
        }
        
        char pk_path[256], sk_path[256];
        snprintf(pk_path, sizeof(pk_path), "%s.pk", argv[3]);
        snprintf(sk_path, sizeof(sk_path), "%s.sk", argv[3]);
        
        printf("[*] Generating ML-KEM-768 keypair. Please wait...\n");
        if (vault_keygen(pk_path, sk_path) == 0) {
            printf("[+] Success! Keys generated:\n");
            printf("    - Public Key (for locking files): %s\n", pk_path);
            printf("    - Secret Key (for unlocking files): %s\n", sk_path);
            printf("\n> CAUTION: Keep %s extremely safe. Losing it means permanent data loss.\n", sk_path);
            return 0;
        } else {
            fprintf(stderr, "[-] Fatal Error: Failed to generate keys.\n");
            return 1;
        }
    } 
    else if (strcmp(argv[1], "seal") == 0) {
        if (argc != 5 || strcmp(argv[2], "--key") != 0) {
            fprintf(stderr, "[-] Error: Invalid format.\nUsage: ./vault seal --key <key.pk> <input_file>\n");
            return 1;
        }
        
        const char *pk_path = argv[3];
        const char *in_file = argv[4];
        
        if (!file_exists(pk_path)) {
            fprintf(stderr, "[-] Error: Public key '%s' not found.\n", pk_path);
            return 1;
        }
        if (!file_exists(in_file)) {
            fprintf(stderr, "[-] Error: Target input file '%s' not found.\n", in_file);
            return 1;
        }

        char out_file[1024];
        snprintf(out_file, sizeof(out_file), "%s.vault", in_file);
        
        printf("[*] Sealing file %s...\n", in_file);
        if (vault_seal(pk_path, in_file, out_file) == 0) {
            printf("[+] Successfully securely encrypted file to: %s\n", out_file);
            return 0;
        } else {
            fprintf(stderr, "[-] Fatal Error: Failed to seal the file.\n");
            return 1;
        }
    } 
    else if (strcmp(argv[1], "open") == 0) {
        if (argc != 5 || strcmp(argv[2], "--key") != 0) {
            fprintf(stderr, "[-] Error: Invalid format.\nUsage: ./vault open --key <key.sk> <vault_file>\n");
            return 1;
        }
        
        const char *sk_path = argv[3];
        const char *vault_file = argv[4];
        
        if (!file_exists(sk_path)) {
            fprintf(stderr, "[-] Error: Secret key '%s' not found.\n", sk_path);
            return 1;
        }
        if (!file_exists(vault_file)) {
            fprintf(stderr, "[-] Error: Encrypted vault file '%s' not found.\n", vault_file);
            return 1;
        }

        // Try to strip exactly ".vault" from the output file name. 
        // If we can't (for some reason it was renamed), just add ".decrypted" to the end.
        char out_file[1024];
        size_t len = strlen(vault_file);
        if (len > 6 && strcmp(vault_file + len - 6, ".vault") == 0) {
            strncpy(out_file, vault_file, len - 6);
            out_file[len - 6] = '\0';
        } else {
            snprintf(out_file, sizeof(out_file), "%s.decrypted", vault_file);
        }

        printf("[*] Opening vault %s...\n", vault_file);
        if (vault_open(sk_path, vault_file, out_file) == 0) {
            printf("[+] Successfully decrypted original file to: %s\n", out_file);
            return 0;
        } else {
            // The tampered check from earlier applies here! A generic error is safer for security boundaries.
            fprintf(stderr, "[-] Fatal Error: Decryption failed! Did someone tamper with the sticker, or use the wrong key?\n");
            return 1;
        }
    } 
    else {
        fprintf(stderr, "[-] Error: Unknown command '%s'\n", argv[1]);
        print_usage();
        return 1;
    }
}
