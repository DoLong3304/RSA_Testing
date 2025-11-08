#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <math.h>
#include <dirent.h>
#include "rsa.h"
#include "test_module.h"
#include <stdint.h>

#define KEYS_DIR "keys"
#define MAX_PATH 256
#define LIMIT_SECONDS 600

static char *sha256_file_hex(const char *path);

static int ensure_keys_dir() {
    struct stat st; if (stat(KEYS_DIR, &st)==0 && S_ISDIR(st.st_mode)) return 0; return mkdir(KEYS_DIR,0700);
}

static void build_key_paths(int bits, char *pub, char *priv) {
    snprintf(pub, MAX_PATH, "%s/public_%d.key", KEYS_DIR, bits);
    snprintf(priv, MAX_PATH, "%s/private_%d.key", KEYS_DIR, bits);
}

void test_bulk_keys(int min_bits, int max_bits) {
    if (min_bits <= 0 || max_bits < min_bits) { fprintf(stderr, "Invalid range.\n"); return; }
    ensure_keys_dir();
    public_key_t pub; private_key_t priv; init_public_key(&pub); init_private_key(&priv);
    for (int bits = min_bits; bits <= max_bits; bits <<= 1) {
        printf("Generating %d-bit key pair... ", bits); fflush(stdout);
        generate_keys(&pub, &priv, bits);
        char pub_path[MAX_PATH], priv_path[MAX_PATH];
        build_key_paths(bits, pub_path, priv_path);
        if (save_public_key(pub_path, &pub) || save_private_key(priv_path, &priv)) {
            printf("FAILED\n");
        } else {
            printf("OK\n");
        }
    }
    clear_public_key(&pub); clear_private_key(&priv);
}

int test_integrity(const char *file_path, int bits) {
    if (!file_path) return -1;
    ensure_keys_dir();
    // If bits <=0, try to detect latest by scanning keys dir.
    if (bits <= 0) {
        int latest = -1; DIR *d = opendir(KEYS_DIR); if (d) { struct dirent *e; while ((e=readdir(d))) {
            if (strncmp(e->d_name, "public_", 7)==0) { char *dot=strchr(e->d_name,'.'); if(dot){ int val=atoi(e->d_name+7); if (val>latest) latest=val; } }
        } closedir(d);} bits = latest; }
    if (bits <= 0) { fprintf(stderr, "No key bits resolved.\n"); return -1; }
    char pub_path[MAX_PATH], priv_path[MAX_PATH]; build_key_paths(bits, pub_path, priv_path);
    public_key_t pub; private_key_t priv; init_public_key(&pub); init_private_key(&priv);
    if (load_public_key(pub_path,&pub) || load_private_key(priv_path,&priv)) { fprintf(stderr,"Failed loading keys.\n"); clear_public_key(&pub); clear_private_key(&priv); return -1; }
    // Encrypt (auto output naming inside encrypt_file) then decrypt
    if (encrypt_file(file_path, NULL, &pub) != 0) { fprintf(stderr,"Encryption failed.\n");}
    // Build encrypted filename
    char enc_path[MAX_PATH]; snprintf(enc_path, MAX_PATH, "%s.dat", file_path);
    if (decrypt_file(enc_path, NULL, &priv) != 0) { fprintf(stderr,"Decryption failed.\n"); }
    // Build decrypted filename
    // Strip .dat then insert _decrypted before extension
    char dec_path[MAX_PATH];
    const char *dot = strrchr(file_path, '.');
    if (dot) {
        size_t base_len = (size_t)(dot - file_path);
        snprintf(dec_path, MAX_PATH, "%.*s_decrypted%s", (int)base_len, file_path, dot);
    } else {
        snprintf(dec_path, MAX_PATH, "%s_decrypted", file_path);
    }
    // Compare original and decrypted plus SHA-256 hashes
    char *orig_hash = sha256_file_hex(file_path);
    char *dec_hash = sha256_file_hex(dec_path);
    if (orig_hash && dec_hash)
        printf("SHA256 original: %s\nSHA256 decrypted: %s\n", orig_hash, dec_hash);
    free(orig_hash); free(dec_hash);
    // Compare original and decrypted
    FILE *f1 = fopen(file_path, "rb"); FILE *f2 = fopen(dec_path, "rb"); if (!f1 || !f2) { fprintf(stderr,"Cannot open files for comparison.\n"); if(f1)fclose(f1); if(f2)fclose(f2); clear_public_key(&pub); clear_private_key(&priv); return -1; }
    int equal = 1; int c1, c2; while ((c1=fgetc(f1))!=EOF && (c2=fgetc(f2))!=EOF) { if (c1!=c2) { equal=0; break; } }
    if (equal && (fgetc(f1)!=EOF || fgetc(f2)!=EOF)) equal=0; fclose(f1); fclose(f2);
    clear_public_key(&pub); clear_private_key(&priv);
    printf("Integrity test (%d bits): %s\n", bits, equal?"PASS":"FAIL");
    return equal?0:-1;
}

void test_speed(const char *file_path, int min_bits, int max_bits) {
    if (!file_path) { fprintf(stderr,"File path required.\n"); return; }
    ensure_keys_dir();
    public_key_t pub; private_key_t priv; init_public_key(&pub); init_private_key(&priv);

    printf("\nSpeed test for '%s' (bits: %d..%d, powers of two)\n", file_path, min_bits, max_bits);
    printf("+---------+------------------+------------------+--------------------+\n");
    printf("|   Bits  |    Encrypt (s)   |    Decrypt (s)   | Encrypted Size (B) |\n");
    printf("+---------+------------------+------------------+--------------------+\n");

    for (int bits = min_bits; bits <= max_bits; bits <<= 1) {
        generate_keys(&pub, &priv, bits);
        char pub_path[MAX_PATH], priv_path[MAX_PATH]; build_key_paths(bits, pub_path, priv_path);
        save_public_key(pub_path,&pub); save_private_key(priv_path,&priv);

        struct timespec ts_enc_start, ts_enc_end, ts_dec_start, ts_dec_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_enc_start);
        if (encrypt_file(file_path, NULL, &pub) != 0) {
            printf("| %7d | %16s | %16s | %18s |\n", bits, "ENCRYPT_FAIL", "-", "-");
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts_enc_end);
        char enc_path[MAX_PATH]; snprintf(enc_path, MAX_PATH, "%s.dat", file_path);
        struct stat st; long long enc_size = -1; if (stat(enc_path, &st) == 0) enc_size = (long long)st.st_size;

        clock_gettime(CLOCK_MONOTONIC, &ts_dec_start);
        if (decrypt_file(enc_path, NULL, &priv) != 0) {
            double enc_secs = (ts_enc_end.tv_sec - ts_enc_start.tv_sec) + (ts_enc_end.tv_nsec - ts_enc_start.tv_nsec)/1e9;
            printf("| %7d | %16.6f | %16s | %18lld |\n", bits, enc_secs, "DECRYPT_FAIL", enc_size);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts_dec_end);

        double enc_secs = (ts_enc_end.tv_sec - ts_enc_start.tv_sec) + (ts_enc_end.tv_nsec - ts_enc_start.tv_nsec)/1e9;
        double dec_secs = (ts_dec_end.tv_sec - ts_dec_start.tv_sec) + (ts_dec_end.tv_nsec - ts_dec_start.tv_nsec)/1e9;
        printf("| %7d | %16.6f | %16.6f | %18lld |\n", bits, enc_secs, dec_secs, enc_size);
    }

    printf("+---------+------------------+------------------+--------------------+\n\n");
    clear_public_key(&pub); clear_private_key(&priv);
}

// Basic trial division factoring (infeasible for large bits, used just for demonstration)
static int factor_n(const mpz_t n, mpz_t p_out, mpz_t q_out, unsigned long limit_seconds) {
    time_t start = time(NULL);
    mpz_t i, rem; mpz_inits(i, rem, NULL); mpz_set_ui(i,2);
    while (mpz_cmp(i, n) < 0) {
        if (difftime(time(NULL), start) > (double)limit_seconds) { mpz_clears(i, rem, NULL); return 0; }
        mpz_mod(rem, n, i);
        if (mpz_cmp_ui(rem,0)==0) {
            mpz_set(p_out, i);
            mpz_divexact(q_out, n, i);
            mpz_clears(i, rem, NULL);
            return 1;
        }
        mpz_add_ui(i, i, 1);
    }
    mpz_clears(i, rem, NULL); return 0;
}

void test_bruteforce(const char *sample_file, int min_bits, int max_bits, int limit_seconds) {
    if (!sample_file) { fprintf(stderr,"Sample file required.\n"); return; }
    if (limit_seconds <= 0) limit_seconds = LIMIT_SECONDS;
    ensure_keys_dir();
    for (int bits=min_bits; bits<=max_bits; bits <<= 1) {
        printf("Bruteforce attempt for %d-bit key (limit %d s)...\n", bits, limit_seconds);
        // Load or generate key
        char pub_path[MAX_PATH], priv_path[MAX_PATH]; build_key_paths(bits, pub_path, priv_path);
        public_key_t pub; private_key_t priv; init_public_key(&pub); init_private_key(&priv);
        int have_keys = (load_public_key(pub_path,&pub)==0 && load_private_key(priv_path,&priv)==0);
        if (!have_keys) {
            generate_keys(&pub,&priv,bits);
            save_public_key(pub_path,&pub); save_private_key(priv_path,&priv);
        }
        // Attempt factoring of n with naive trial division up to 600 seconds (10 minutes)
        mpz_t p,q; mpz_inits(p,q,NULL);
        struct timespec ts_start, ts_end; clock_gettime(CLOCK_MONOTONIC,&ts_start);
        int success = factor_n(pub.n, p, q, (unsigned long)limit_seconds);
        clock_gettime(CLOCK_MONOTONIC,&ts_end);
        double elapsed = (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec)/1e9;
        if (!success) {
            printf("Result %d bits: Too long (%.2f s)\n", bits, elapsed);
            mpz_clears(p,q,NULL);
            clear_public_key(&pub); clear_private_key(&priv);
            continue;
        }
        // Reconstruct private key and test decrypt
        mpz_t phi, p1, q1, d_calc; mpz_inits(phi,p1,q1,d_calc,NULL);
        mpz_sub_ui(p1,p,1); mpz_sub_ui(q1,q,1); mpz_mul(phi,p1,q1);
        if (mpz_invert(d_calc, pub.e, phi)==0) {
            printf("Result %d bits: Inversion failed after factoring (%.2f s)\n", bits, elapsed);
        } else {
            // Encrypt sample file then decrypt using recovered d to validate
            private_key_t recovered; init_private_key(&recovered); mpz_set(recovered.n, pub.n); mpz_set(recovered.d, d_calc);
            if (encrypt_file(sample_file, NULL, &pub)==0) {
                char enc_path[MAX_PATH]; snprintf(enc_path, MAX_PATH, "%s.dat", sample_file);
                if (decrypt_file(enc_path, NULL, &recovered)==0) {
                    printf("Result %d bits: SUCCESS brute forced in %.2f s\n", bits, elapsed);
                } else {
                    printf("Result %d bits: Factored but decrypt failed (%.2f s)\n", bits, elapsed);
                }
            } else {
                printf("Result %d bits: Factored but encryption test failed (%.2f s)\n", bits, elapsed);
            }
            clear_private_key(&recovered);
        }
        mpz_clears(phi,p1,q1,d_calc,p,q,NULL);
        clear_public_key(&pub); clear_private_key(&priv);
    }
}

// SHA-256 implementation (public domain) for file integrity
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} sha256_ctx;

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x393f11b,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    for (uint32_t i=0,j=0;i<16;i++,j+=4)
        m[i] = (data[j]<<24)|(data[j+1]<<16)|(data[j+2]<<8)|(data[j+3]);
    for (uint32_t i=16;i<64;i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (uint32_t i=0;i<64;i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i=0;i<len;i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen==64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen=0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data,0,56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i=0;i<4;i++) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i+4]    = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i+8]    = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i+12]   = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i+16]   = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i+20]   = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i+24]   = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i+28]   = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static char *sha256_file_hex(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    sha256_ctx ctx; sha256_init(&ctx);
    uint8_t buf[4096]; size_t r;
    while ((r=fread(buf,1,sizeof(buf),f))>0) sha256_update(&ctx, buf, r);
    fclose(f);
    uint8_t hash[32]; sha256_final(&ctx, hash);
    char *hex = malloc(65); if (!hex) return NULL; for (int i=0;i<32;i++) sprintf(hex + i*2, "%02x", hash[i]); hex[64]='\0';
    return hex;
}
