#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

// --- Constants for filenames and buffer sizes ---
#define PUBLIC_KEY_FILE "public.key"
#define PRIVATE_KEY_FILE "private.key"
#define MAX_PATH_LEN 256
#define DEFAULT_BIT_LEN 2048

// --- Function Prototypes for Logic ---
int do_key_generation(int bit_length);
int do_file_encryption(const char *input_path, const char *output_path);
int do_file_decryption(const char *input_path, const char *output_path);

// --- Function Prototypes for UI ---
void print_menu();
void handle_key_generation_interactive();
void handle_file_encryption_interactive();
void handle_file_decryption_interactive();
void run_interactive_mode();
void print_usage(const char *prog_name);

// --- Main Function ---
int main(int argc, char *argv[]) {
    if (argc == 1) {
        run_interactive_mode();
        return 0;
    }

    if (strcmp(argv[1], "generate") == 0) {
        int bit_length = DEFAULT_BIT_LEN;
        if (argc > 2) {
            bit_length = atoi(argv[2]);
        }
        return do_key_generation(bit_length);
    } else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Missing input/output file paths for encryption.\n");
            print_usage(argv[0]);
            return 1;
        }
        return do_file_encryption(argv[2], argv[3]);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Missing input/output file paths for decryption.\n");
            print_usage(argv[0]);
            return 1;
        }
        return do_file_decryption(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}


// --- Core Logic Functions ---

int do_key_generation(int bit_length) {
    if (bit_length < 512) {
        printf("Warning: Bit length is too short. Using 512 bits minimum.\n");
        bit_length = 512;
    }

    printf("Generating %d-bit RSA keys... ", bit_length);
    fflush(stdout);

    public_key_t pub;
    private_key_t priv;
    init_public_key(&pub);
    init_private_key(&priv);

    generate_keys(&pub, &priv, bit_length);

    int result = 0;
    if (save_public_key(PUBLIC_KEY_FILE, &pub) != 0) {
        fprintf(stderr, "\nError saving public key.\n");
        result = -1;
    } else if (save_private_key(PRIVATE_KEY_FILE, &priv) != 0) {
        fprintf(stderr, "\nError saving private key.\n");
        result = -1;
    } else {
        printf("Done.\n");
        printf("Keys saved to '%s' and '%s'.\n", PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
    }

    clear_public_key(&pub);
    clear_private_key(&priv);
    return result;
}

int do_file_encryption(const char *input_path, const char *output_path) {
    public_key_t pub;
    init_public_key(&pub);

    if (load_public_key(PUBLIC_KEY_FILE, &pub) != 0) {
        fprintf(stderr, "Error: Could not load public key from '%s'. Generate keys first.\n", PUBLIC_KEY_FILE);
        clear_public_key(&pub);
        return -1;
    }

    printf("Encrypting '%s' to '%s'... ", input_path, output_path);
    fflush(stdout);

    int result = 0;
    if (encrypt_file(input_path, output_path, &pub) == 0) {
        printf("Done.\n");
    } else {
        fprintf(stderr, "\nEncryption failed.\n");
        result = -1;
    }

    clear_public_key(&pub);
    return result;
}

int do_file_decryption(const char *input_path, const char *output_path) {
    private_key_t priv;
    init_private_key(&priv);

    if (load_private_key(PRIVATE_KEY_FILE, &priv) != 0) {
        fprintf(stderr, "Error: Could not load private key from '%s'. Generate keys first.\n", PRIVATE_KEY_FILE);
        clear_private_key(&priv);
        return -1;
    }

    printf("Decrypting '%s' to '%s'... ", input_path, output_path);
    fflush(stdout);

    int result = 0;
    if (decrypt_file(input_path, output_path, &priv) == 0) {
        printf("Done.\n");
    } else {
        fprintf(stderr, "\nDecryption failed.\n");
        result = -1;
    }

    clear_private_key(&priv);
    return result;
}

// --- Interactive UI and Handler Functions ---

void run_interactive_mode() {
    int choice = 0;
    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input. Please enter a number.\n\n");
            continue;
        }

        while (getchar() != '\n');

        switch (choice) {
            case 1:
                handle_key_generation_interactive();
                break;
            case 2:
                handle_file_encryption_interactive();
                break;
            case 3:
                handle_file_decryption_interactive();
                break;
            case 4:
                printf("Exiting program.\n");
                return;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
        printf("\n");
    }
}

void print_menu() {
    printf("=================================\n");
    printf("        RSA Cryptography Tool\n");
    printf("=================================\n");
    printf("1. Generate new RSA keys\n");
    printf("2. Encrypt a file\n");
    printf("3. Decrypt a file\n");
    printf("4. Exit\n");
    printf("---------------------------------\n");
    printf("Enter your choice: ");
}

void print_usage(const char *prog_name) {
    printf("\nUsage:\n");
    printf("  %s                         : Run in interactive mode.\n", prog_name);
    printf("  %s generate [bit_length]   : Generate new keys (default bits: %d).\n", prog_name, DEFAULT_BIT_LEN);
    printf("  %s encrypt <infile> <outfile> : Encrypt a file using public.key.\n", prog_name);
    printf("  %s decrypt <infile> <outfile> : Decrypt a file using private.key.\n", prog_name);
}


void handle_key_generation_interactive() {
    char bit_len_str[16];
    int bit_length;

    printf("Enter key bit length (default is %d, press Enter to use default): ", DEFAULT_BIT_LEN);
    fgets(bit_len_str, sizeof(bit_len_str), stdin);

    if (strlen(bit_len_str) > 1 && sscanf(bit_len_str, "%d", &bit_length) == 1) {
    } else {
        bit_length = DEFAULT_BIT_LEN;
    }

    do_key_generation(bit_length);
}

void handle_file_encryption_interactive() {
    char input_file[MAX_PATH_LEN];
    char output_file[MAX_PATH_LEN];

    printf("Enter path of the file to encrypt: ");
    if (!fgets(input_file, sizeof(input_file), stdin)) return;
    input_file[strcspn(input_file, "\n")] = 0;

    printf("Enter path for the encrypted output file: ");
    if (!fgets(output_file, sizeof(output_file), stdin)) return;
    output_file[strcspn(output_file, "\n")] = 0;

    do_file_encryption(input_file, output_file);
}

void handle_file_decryption_interactive() {
    char input_file[MAX_PATH_LEN];
    char output_file[MAX_PATH_LEN];

    printf("Enter path of the file to decrypt: ");
    if (!fgets(input_file, sizeof(input_file), stdin)) return;
    input_file[strcspn(input_file, "\n")] = 0;

    printf("Enter path for the decrypted output file: ");
    if (!fgets(output_file, sizeof(output_file), stdin)) return;
    output_file[strcspn(output_file, "\n")] = 0;

    do_file_decryption(input_file, output_file);
}

