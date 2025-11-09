#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "rsa.h"
#include "test_module.h"

#if defined(_WIN32)
#include <windows.h>
#include <direct.h>
#define MKDIR_DIR(path) _mkdir(path)
#else
#include <unistd.h>
#define MKDIR_DIR(path) mkdir(path, 0700)
#endif

#define MAX_PATH_LEN 256
#define DEFAULT_BIT_LEN 2048
#define KEYS_DIR "keys"
#define LIMIT_SECONDS 600 // Default time limit for brute force test

// --- Function Prototypes for Logic ---
int do_key_generation(int bit_length);
int do_file_encryption(const char *input_path, const char *output_path, int key_bits);
int do_file_decryption(const char *input_path, const char *output_path, int key_bits);

// --- Helper Prototypes ---
static int ensure_keys_dir();
static int find_latest_key_bits();
static void build_key_paths(int bits, char *pub_path, char *priv_path, size_t sz);

// --- UI Prototypes ---
void print_menu();
void handle_key_generation_interactive();
void handle_file_encryption_interactive();
void handle_file_decryption_interactive();
void handle_test_bulk_interactive();
void handle_test_integrity_interactive();
void handle_test_speed_interactive();
void handle_test_bruteforce_interactive();
void run_interactive_mode();
void print_usage(const char *prog_name);

static long safe_strtol(const char *s) {
    char *end=NULL;
    long v=strtol(s,&end,10);
    if(end&&*end!='\0'&&*end!='\n') return -1;
    return v;
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        run_interactive_mode();
        return 0;
    }

    if (strcmp(argv[1], "generate") == 0) {
        int bit_length = DEFAULT_BIT_LEN;
        if (argc > 2) { long v=safe_strtol(argv[2]); if(v>0) bit_length=(int)v; }
        if (bit_length <= 0) {
            fprintf(stderr, "Invalid bit length.\n");
            return 1;
        }
        return do_key_generation(bit_length);
    } else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing input file path for encryption.\n");
            print_usage(argv[0]);
            return 1;
        }
        const char *infile = argv[2];
        int key_bits = -1;
        const char *outfile = NULL;
        if (argc >= 4) {
            // Could be bits or outfile; detect if numeric
            char *endptr = NULL;
            long val = strtol(argv[3], &endptr, 10);
            if (endptr && *endptr == '\0' && val > 0) {
                key_bits = (int)val;
                if (argc >= 5) outfile = argv[4];
            } else {
                outfile = argv[3];
            }
        }
        return do_file_encryption(infile, outfile, key_bits);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing input file path for decryption.\n");
            print_usage(argv[0]);
            return 1;
        }
        const char *infile = argv[2];
        int key_bits = -1;
        const char *outfile = NULL;
        if (argc >= 4) {
            char *endptr = NULL;
            long val = strtol(argv[3], &endptr, 10);
            if (endptr && *endptr == '\0' && val > 0) {
                key_bits = (int)val;
                if (argc >= 5) outfile = argv[4];
            } else {
                outfile = argv[3];
            }
        }
        return do_file_decryption(infile, outfile, key_bits);
    } else if (strcmp(argv[1], "test") == 0) {
        if (argc < 3) { print_usage(argv[0]); return 1; }
        const char *sub = argv[2];
        if (strcmp(sub, "bulk") == 0) {
            if (argc < 5) { fprintf(stderr, "Usage: %s test bulk <min_bits> <max_bits>\n", argv[0]); return 1; }
            int min_bits = (int)safe_strtol(argv[3]); int max_bits = (int)safe_strtol(argv[4]);
            test_bulk_keys(min_bits, max_bits);
            return 0;
        } else if (strcmp(sub, "integrity") == 0) {
            if (argc < 4) { fprintf(stderr, "Usage: %s test integrity <file> [bits]\n", argv[0]); return 1; }
            const char *file = argv[3]; int bits = -1; if (argc >= 5) { long v=safe_strtol(argv[4]); if(v>0) bits=(int)v; }
            return test_integrity(file, bits);
        } else if (strcmp(sub, "speed") == 0) {
            if (argc < 6) { fprintf(stderr, "Usage: %s test speed <file> <min_bits> <max_bits>\n", argv[0]); return 1; }
            const char *file = argv[3]; int min_bits = (int)safe_strtol(argv[4]); int max_bits = (int)safe_strtol(argv[5]);
            test_speed(file, min_bits, max_bits); return 0;
        } else if (strcmp(sub, "bruteforce") == 0) {
            if (argc < 6) { fprintf(stderr, "Usage: %s test bruteforce <file> <min_bits> <max_bits> [limit_seconds] [algorithm]\n", argv[0]); return 1; }
            const char *file = argv[3]; int min_bits = (int)safe_strtol(argv[4]); int max_bits = (int)safe_strtol(argv[5]);
            int limit_seconds = LIMIT_SECONDS; const char *algo = "auto";
            if (argc >= 7) { long v=safe_strtol(argv[6]); if(v>0) limit_seconds=(int)v; }
            if (argc >= 8) algo = argv[7];
            test_bruteforce(file, min_bits, max_bits, limit_seconds, algo); return 0;
        } else {
            fprintf(stderr, "Unknown test subcommand '%s'.\n", sub); print_usage(argv[0]); return 1;
        }
    } else {
        fprintf(stderr, "Error: Unknown command '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}

// --- Helper Implementations ---
static int ensure_keys_dir() {
    struct stat st;
    if (stat(KEYS_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "'%s' exists but is not a directory.\n", KEYS_DIR);
            return -1;
        }
        return 0;
    }
    if (MKDIR_DIR(KEYS_DIR) != 0) {
        perror("Failed to create keys directory");
        return -1;
    }
    return 0;
}

static int parse_bits_from_filename(const char *name) {
    // Expect pattern public_<bits>.key or private_<bits>.key
    const char *pub_prefix = "public_";
    const char *priv_prefix = "private_";
    const char *prefix = NULL;
    if (strncmp(name, pub_prefix, strlen(pub_prefix)) == 0) prefix = pub_prefix;
    else if (strncmp(name, priv_prefix, strlen(priv_prefix)) == 0) prefix = priv_prefix;
    else return -1;

    const char *after = name + strlen(prefix);
    const char *dot = strchr(after, '.');
    if (!dot) return -1;
    char buf[32];
    size_t len = (size_t)(dot - after);
    if (len == 0 || len >= sizeof(buf)) return -1;
    memcpy(buf, after, len);
    buf[len] = '\0';
    char *endptr = NULL;
    long val = strtol(buf, &endptr, 10);
    if (endptr && *endptr == '\0' && val > 0) return (int)val;
    return -1;
}

static int find_latest_key_bits() {
#if defined(_WIN32)
    char pattern[MAX_PATH_LEN];
    snprintf(pattern, sizeof(pattern), "%s\\*.key", KEYS_DIR);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int latest_bits = -1;
    do {
        const char *name = fd.cFileName;
        if (strncmp(name, "public_", 7)==0 || strncmp(name, "private_", 8)==0) {
            int bits = parse_bits_from_filename(name);
            if (bits > latest_bits) latest_bits = bits;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return latest_bits;
#else
    DIR *dir = opendir(KEYS_DIR);
    if (!dir) return -1;
    struct dirent *entry;
    int latest_bits = -1;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strncmp(name, "public_", 7)==0 || strncmp(name, "private_", 8)==0) {
            int bits = parse_bits_from_filename(name);
            if (bits > latest_bits) latest_bits = bits;
        }
    }
    closedir(dir);
    return latest_bits;
#endif
}

static void build_key_paths(int bits, char *pub_path, char *priv_path, size_t sz) {
    snprintf(pub_path, sz, "%s/public_%d.key", KEYS_DIR, bits);
    snprintf(priv_path, sz, "%s/private_%d.key", KEYS_DIR, bits);
}

// --- Core Logic Functions ---
int do_key_generation(int bit_length) {
    if (bit_length <= 0) {
        fprintf(stderr, "Bit length must be positive.\n");
        return -1;
    }
    if (ensure_keys_dir() != 0) return -1;

    printf("Generating %d-bit RSA keys... ", bit_length);
    fflush(stdout);

    public_key_t pub;
    private_key_t priv;
    init_public_key(&pub);
    init_private_key(&priv);

    generate_keys(&pub, &priv, bit_length);

    char pub_path[MAX_PATH_LEN];
    char priv_path[MAX_PATH_LEN];
    build_key_paths(bit_length, pub_path, priv_path, sizeof(pub_path));

    int result = 0;
    if (save_public_key(pub_path, &pub) != 0) {
        fprintf(stderr, "\nError saving public key to %s.\n", pub_path);
        result = -1;
    } else if (save_private_key(priv_path, &priv) != 0) {
        fprintf(stderr, "\nError saving private key to %s.\n", priv_path);
        result = -1;
    } else {
        printf("Done.\nKeys saved to '%s' and '%s'.\n", pub_path, priv_path);
    }

    clear_public_key(&pub);
    clear_private_key(&priv);
    return result;
}

int do_file_encryption(const char *input_path, const char *output_path, int key_bits) {
    if (ensure_keys_dir() != 0) return -1;
    if (key_bits <= 0) {
        key_bits = find_latest_key_bits();
        if (key_bits <= 0) {
            fprintf(stderr, "No keys found. Generate keys first.\n");
            return -1;
        }
    }

    char pub_path[MAX_PATH_LEN];
    char priv_dummy[MAX_PATH_LEN];
    build_key_paths(key_bits, pub_path, priv_dummy, sizeof(pub_path));

    public_key_t pub;
    init_public_key(&pub);
    if (load_public_key(pub_path, &pub) != 0) {
        fprintf(stderr, "Error: Could not load public key '%s'.\n", pub_path);
        clear_public_key(&pub);
        return -1;
    }

    const char *out_display = output_path ? output_path : "(auto)";
    printf("Encrypting '%s' to '%s' using %d-bit key... ", input_path, out_display, key_bits);
    fflush(stdout);

    int result = 0;
    if (encrypt_file(input_path, output_path, &pub) == 0) {
        printf("Done.\n");
        if (!output_path) {
            printf("Output file: %s.dat\n", input_path);
        }
    } else {
        fprintf(stderr, "\nEncryption failed.\n");
        result = -1;
    }

    clear_public_key(&pub);
    return result;
}

int do_file_decryption(const char *input_path, const char *output_path, int key_bits) {
    if (ensure_keys_dir() != 0) return -1;
    if (key_bits <= 0) {
        key_bits = find_latest_key_bits();
        if (key_bits <= 0) {
            fprintf(stderr, "No keys found. Generate keys first.\n");
            return -1;
        }
    }

    char priv_path[MAX_PATH_LEN];
    char pub_dummy[MAX_PATH_LEN];
    build_key_paths(key_bits, pub_dummy, priv_path, sizeof(priv_path));

    private_key_t priv;
    init_private_key(&priv);
    if (load_private_key(priv_path, &priv) != 0) {
        fprintf(stderr, "Error: Could not load private key '%s'.\n", priv_path);
        clear_private_key(&priv);
        return -1;
    }

    const char *out_display = output_path ? output_path : "(auto)";
    printf("Decrypting '%s' to '%s' using %d-bit key... ", input_path, out_display, key_bits);
    fflush(stdout);

    int result = 0;
    if (decrypt_file(input_path, output_path, &priv) == 0) {
        printf("Done.\n");
        if (!output_path) {
            // Decrypted output name derived inside decrypt_file
            printf("Output file generated automatically.\n");
        }
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
    char choice_buf[16];
    while (1) {
        print_menu();
        if (!fgets(choice_buf, sizeof(choice_buf), stdin)) return;
        long v = safe_strtol(choice_buf);
        if (v < 1 || v > 8) {
            printf("Invalid input. Please enter a number.\n\n");
            continue;
        }
        choice = (int)v;
        switch (choice) {
            case 1: handle_key_generation_interactive(); break;
            case 2: handle_file_encryption_interactive(); break;
            case 3: handle_file_decryption_interactive(); break;
            case 4: handle_test_bulk_interactive(); break;
            case 5: handle_test_integrity_interactive(); break;
            case 6: handle_test_speed_interactive(); break;
            case 7: handle_test_bruteforce_interactive(); break;
            case 8: printf("Exiting program.\n"); return;
            default: printf("Invalid choice. Please try again.\n"); break;
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
    printf("4. Test: Bulk key generation\n");
    printf("5. Test: Integrity check\n");
    printf("6. Test: Speed benchmark\n");
    printf("7. Test: Brute force key (demo)\n");
    printf("8. Exit\n");
    printf("---------------------------------\n");
    printf("Enter your choice: ");
}

void print_usage(const char *prog_name) {
    printf("\nUsage:\n");
    printf("  %s generate [bit_length]           : Generate new keys. Default %d bits.\n", prog_name, DEFAULT_BIT_LEN);
    printf("  %s encrypt <infile> [bits] [outfile] : Encrypt file. Auto-output if omitted.\n", prog_name);
    printf("  %s decrypt <infile> [bits] [outfile] : Decrypt file. Auto-output if omitted.\n", prog_name);
    printf("  %s test bulk <min_bits> <max_bits>           : Generate multiple key pairs (powers of two).\n", prog_name);
    printf("  %s test integrity <file> [bits]              : Encrypt/decrypt and verify match.\n", prog_name);
    printf("  %s test speed <file> <min_bits> <max_bits>   : Measure performance across bit sizes.\n", prog_name);
    printf("  %s test bruteforce <file> <min_bits> <max_bits> [limit_seconds] [algorithm] : Attempt factoring (algo: auto|trial|rho|p1).\n", prog_name);
}

void handle_key_generation_interactive() {
    char bit_len_str[32];
    int bit_length = DEFAULT_BIT_LEN;
    printf("Enter key bit length (default %d): ", DEFAULT_BIT_LEN);
    if (fgets(bit_len_str, sizeof(bit_len_str), stdin)) { long v=safe_strtol(bit_len_str); if (v>0) bit_length=(int)v; }
    do_key_generation(bit_length);
}

void handle_file_encryption_interactive() {
    char input_file[MAX_PATH_LEN];
    char bits_str[32];
    char out_file[MAX_PATH_LEN];

    printf("Enter path of file to encrypt: ");
    if (!fgets(input_file, sizeof(input_file), stdin)) return;
    input_file[strcspn(input_file, "\n")] = 0;

    printf("Enter key bits to use (leave empty for latest): ");
    if (!fgets(bits_str, sizeof(bits_str), stdin)) return;

    int bits = -1;
    if (strlen(bits_str) > 1) { long v=safe_strtol(bits_str); if(v>0) bits=(int)v; }

    printf("Enter output filename (leave empty for auto .dat): ");
    if (!fgets(out_file, sizeof(out_file), stdin)) return;
    out_file[strcspn(out_file, "\n")] = 0;
    const char *out_ptr = strlen(out_file) ? out_file : NULL;

    do_file_encryption(input_file, out_ptr, bits);
}

void handle_file_decryption_interactive() {
    char input_file[MAX_PATH_LEN];
    char bits_str[32];
    char out_file[MAX_PATH_LEN];

    printf("Enter path of file to decrypt (.dat): ");
    if (!fgets(input_file, sizeof(input_file), stdin)) return;
    input_file[strcspn(input_file, "\n")] = 0;

    printf("Enter key bits to use (leave empty for latest): ");
    if (!fgets(bits_str, sizeof(bits_str), stdin)) return;
    int bits = -1;
    if (strlen(bits_str) > 1) { long v=safe_strtol(bits_str); if(v>0) bits=(int)v; }

    printf("Enter output filename (leave empty for auto *_decrypted): ");
    if (!fgets(out_file, sizeof(out_file), stdin)) return;
    out_file[strcspn(out_file, "\n")] = 0;
    const char *out_ptr = strlen(out_file) ? out_file : NULL;

    do_file_decryption(input_file, out_ptr, bits);
}

void handle_test_bulk_interactive() {
    int min_bits, max_bits;
    char min_buf[32], max_buf[32];
    printf("Enter min bit length: "); if(!fgets(min_buf,sizeof(min_buf),stdin)) return; long mv=safe_strtol(min_buf); if(mv<=0){printf("Invalid.\n"); return;} min_bits=(int)mv;
    printf("Enter max bit length: "); if(!fgets(max_buf,sizeof(max_buf),stdin)) return; long xv=safe_strtol(max_buf); if(xv<=0){printf("Invalid.\n"); return;} max_bits=(int)xv;
    while (getchar()!='\n') {}
    test_bulk_keys(min_bits, max_bits);
}

void handle_test_integrity_interactive() {
    char path[MAX_PATH_LEN]; char bits_str[32];
    printf("Enter file to test integrity: "); if (!fgets(path, sizeof(path), stdin)) return; path[strcspn(path, "\n")] = 0;
    printf("Enter bits to use (leave empty for latest): "); if (!fgets(bits_str, sizeof(bits_str), stdin)) return;
    int bits = -1; if (strlen(bits_str) > 1) { long v=safe_strtol(bits_str); if(v>0) bits=(int)v; }
    test_integrity(path, bits);
}

void handle_test_speed_interactive() {
    char path[MAX_PATH_LEN]; int min_bits, max_bits; char min_buf[32], max_buf[32];
    printf("Enter file to benchmark: "); if (!fgets(path, sizeof(path), stdin)) return; path[strcspn(path, "\n")] = 0;
    printf("Enter min bit length: "); if(!fgets(min_buf,sizeof(min_buf),stdin)) return; long mv=safe_strtol(min_buf); if(mv<=0){printf("Invalid.\n"); return;} min_bits=(int)mv;
    printf("Enter max bit length: "); if(!fgets(max_buf,sizeof(max_buf),stdin)) return; long xv=safe_strtol(max_buf); if(xv<=0){printf("Invalid.\n"); return;} max_bits=(int)xv;
    test_speed(path, min_bits, max_bits);
}

void handle_test_bruteforce_interactive() {
    char path[MAX_PATH_LEN]; int min_bits, max_bits; char limit_str[32]; char algo_str[32]; char min_bf[32], max_bf[32];
    printf("Enter sample file path: "); if (!fgets(path, sizeof(path), stdin)) return; path[strcspn(path, "\n")] = 0;
    printf("Enter min bit length to attempt: "); if(!fgets(min_bf,sizeof(min_bf),stdin)) return; long mbfv=safe_strtol(min_bf); if(mbfv<=0){printf("Invalid.\n"); return;} min_bits=(int)mbfv;
    printf("Enter max bit length to attempt: "); if(!fgets(max_bf,sizeof(max_bf),stdin)) return; long xbfv=safe_strtol(max_bf); if(xbfv<=0){printf("Invalid.\n"); return;} max_bits=(int)xbfv;
    printf("Enter time limit seconds per key (press Enter for default %d): ", LIMIT_SECONDS);
    if (!fgets(limit_str, sizeof(limit_str), stdin)) return;
    int limit_seconds = LIMIT_SECONDS; if (strlen(limit_str) > 1) { long v=safe_strtol(limit_str); if(v>0) limit_seconds=(int)v; }
    printf("Algorithm (auto|trial|rho|p1) [auto]: "); if (!fgets(algo_str, sizeof(algo_str), stdin)) return; algo_str[strcspn(algo_str, "\n")] = 0;
    const char *algo = (strlen(algo_str) ? algo_str : "auto");
    test_bruteforce(path, min_bits, max_bits, limit_seconds, algo);
}
