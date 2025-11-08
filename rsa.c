/*
 * RSA Cryptography Tool
 * Copyright (c) 2025
 * Licensed under the MIT License. See LICENSE file in the project root.
 */

#include <stdio.h>
#include "rsa.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>

void init_public_key(public_key_t *key) {
    mpz_inits(key->n, key->e, NULL);
}

void init_private_key(private_key_t *key) {
    mpz_inits(key->n, key->d, NULL);
}

void clear_public_key(public_key_t *key) {
    mpz_clears(key->n, key->e, NULL);
}

void clear_private_key(private_key_t *key) {
    mpz_clears(key->n, key->d, NULL);
}

// Generate a random prime with approximately `bits` bits.
// For bits < 2, fallback to at least 2 bits to avoid impossible requests.
static void generate_prime(mpz_t prime, unsigned int bits, gmp_randstate_t rand_state) {
    if (bits < 2) bits = 2; // ensure feasibility
    // generate a random number with the top bit set to target the bit size
    mpz_urandomb(prime, rand_state, bits);
    mpz_setbit(prime, bits - 1);
    // find the next prime >= candidate
    mpz_nextprime(prime, prime);
}

// Derive default encrypted output path: <input> + ".dat"
static char *derive_encrypt_output_path(const char *input_path) {
    size_t len = strlen(input_path);
    const char *suffix = ".dat";
    char *out = (char *)malloc(len + strlen(suffix) + 1);
    if (!out) return NULL;
    strcpy(out, input_path);
    strcat(out, suffix);
    return out;
}

// Derive default decrypted output path: remove trailing .dat if present, then insert
// "_decrypted" before last '.' of the remaining filename, else append at end.
static char *derive_decrypt_output_path(const char *input_path) {
    size_t len = strlen(input_path);
    const char *dat = ".dat";
    size_t dat_len = 4;
    // Make a working copy without the final .dat if present
    char *base = NULL;
    if (len > dat_len && strcmp(input_path + len - dat_len, dat) == 0) {
        base = (char *)malloc(len - dat_len + 1);
        if (!base) return NULL;
        memcpy(base, input_path, len - dat_len);
        base[len - dat_len] = '\0';
    } else {
        base = strdup(input_path);
        if (!base) return NULL;
    }

    // Find last '.' after the last path separator
    const char *slash = strrchr(base, '/');
    const char *search_start = slash ? slash + 1 : base;
    char *last_dot = strrchr(search_start, '.');

    const char *insert = "_decrypted";
    char *result = NULL;
    if (last_dot) {
        size_t left_len = (size_t)(last_dot - base);
        size_t insert_len = strlen(insert);
        size_t right_len = strlen(last_dot); // includes the dot and extension
        result = (char *)malloc(left_len + insert_len + right_len + 1);
        if (!result) { free(base); return NULL; }
        memcpy(result, base, left_len);
        memcpy(result + left_len, insert, insert_len);
        memcpy(result + left_len + insert_len, last_dot, right_len + 1);
    } else {
        size_t insert_len = strlen(insert);
        size_t base_len = strlen(base);
        result = (char *)malloc(base_len + insert_len + 1);
        if (!result) { free(base); return NULL; }
        memcpy(result, base, base_len);
        memcpy(result + base_len, insert, insert_len + 1);
    }

    free(base);
    return result;
}

void generate_keys(public_key_t *pub, private_key_t *priv, unsigned int bit_length) {
    mpz_t p, q, phi;
    mpz_inits(p, q, phi, NULL);
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, (unsigned long)time(NULL));

    // Split target bit length roughly in half for p and q
    unsigned int prime_bits = bit_length / 2;
    if (prime_bits < 2) prime_bits = 2; // ensure primes are valid

    // Generate distinct primes p and q
    generate_prime(p, prime_bits, rand_state);
    do {
        generate_prime(q, prime_bits, rand_state);
    } while (mpz_cmp(p, q) == 0);

    // n = p * q
    mpz_mul(pub->n, p, q);
    mpz_set(priv->n, pub->n);

    // phi = (p-1)*(q-1)
    mpz_t p_minus_1, q_minus_1;
    mpz_inits(p_minus_1, q_minus_1, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);

    // Randomly choose e such that 1 < e < phi and gcd(e, phi) = 1, then compute d = e^{-1} mod phi
    mpz_t e, d, g, phi_minus_1, tmp;
    mpz_inits(e, d, g, phi_minus_1, tmp, NULL);
    mpz_sub_ui(phi_minus_1, phi, 1);

    // If phi <= 2, it's mathematically impossible to choose a valid e
    if (mpz_cmp_ui(phi, 3) < 0) {
        fprintf(stderr, "Error: phi(n) too small; cannot generate valid RSA exponents.\n");
        mpz_clears(p, q, phi, p_minus_1, q_minus_1, e, d, g, phi_minus_1, tmp, NULL);
        gmp_randclear(rand_state);
        exit(1);
    }

    unsigned long phi_bits = mpz_sizeinbase(phi, 2);

    // Select the first random e in (2, phi-1) with gcd(e, phi)=1 and invertible mod phi
    while (1) {
        mpz_urandomb(e, rand_state, phi_bits);
        if (phi_bits > 1) mpz_setbit(e, phi_bits - 1); // broaden distribution
        mpz_mod(e, e, phi_minus_1);
        mpz_add_ui(e, e, 2); // ensure e >= 2
        if (mpz_cmp(e, phi) >= 0) {
            mpz_mod(e, e, phi_minus_1);
            mpz_add_ui(e, e, 2);
        }
        mpz_gcd(g, e, phi);
        if (mpz_cmp_ui(g, 1) != 0) continue;
        if (mpz_invert(d, e, phi) == 0) continue; // extremely unlikely if gcd==1
        break; // accept first valid e
    }

    // Set pub->e and priv->d
    mpz_set(pub->e, e);
    mpz_set(priv->d, d);

    // Cleanup
    mpz_clears(p, q, phi, p_minus_1, q_minus_1, e, d, g, phi_minus_1, tmp, NULL);
    gmp_randclear(rand_state);
}

int encrypt_file(const char *input_path, const char *output_path, const public_key_t *pub) {
    FILE *in_file = fopen(input_path, "rb");
    FILE *out_file = NULL;
    char *auto_out = NULL;
    unsigned char *buffer = NULL;
    mpz_t m, c; mpz_init(m); mpz_init(c);
    int status = -1;

    if (!in_file) { perror("Error opening input file for encryption"); goto cleanup; }

    const char *out_path = output_path;
    if (!out_path) {
        auto_out = derive_encrypt_output_path(input_path);
        if (!auto_out) { fprintf(stderr, "Failed to generate output filename.\n"); goto cleanup; }
        out_path = auto_out;
    }
    out_file = fopen(out_path, "w");
    if (!out_file) { perror("Error opening output file for encryption"); goto cleanup; }

    size_t key_bytes = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
    size_t chunk_size = key_bytes ? key_bytes - 1 : 1;
    if (chunk_size == 0) chunk_size = 1;
    buffer = (unsigned char *)malloc(chunk_size);
    if (!buffer) { fprintf(stderr, "Memory allocation failed.\n"); goto cleanup; }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, chunk_size, in_file)) > 0) {
        mpz_import(m, bytes_read, 1, sizeof(unsigned char), 0, 0, buffer);
        mpz_powm(c, m, pub->e, pub->n);
        gmp_fprintf(out_file, "%Zx\n", c);
    }
    status = 0; // success

cleanup:
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
    if (buffer) free(buffer);
    if (auto_out) free(auto_out);
    mpz_clear(m); mpz_clear(c);
    return status;
}

int decrypt_file(const char *input_path, const char *output_path, const private_key_t *priv) {
    FILE *in_file = fopen(input_path, "r");
    FILE *out_file = NULL;
    char *auto_out = NULL;
    mpz_t c, m; mpz_init(c); mpz_init(m);
    int status = -1;

    if (!in_file) { perror("Error opening input file for decryption"); goto cleanup; }

    const char *out_path = output_path;
    if (!out_path) {
        auto_out = derive_decrypt_output_path(input_path);
        if (!auto_out) { fprintf(stderr, "Failed to generate output filename.\n"); goto cleanup; }
        out_path = auto_out;
    }
    out_file = fopen(out_path, "wb");
    if (!out_file) { perror("Error opening output file for decryption"); goto cleanup; }

    while (gmp_fscanf(in_file, "%Zx\n", c) == 1) {
        mpz_powm(m, c, priv->d, priv->n);
        size_t size; unsigned char *buffer = mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, m);
        if (buffer) { fwrite(buffer, 1, size, out_file); free(buffer); }
    }
    status = 0;

cleanup:
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
    if (auto_out) free(auto_out);
    mpz_clear(c); mpz_clear(m);
    return status;
}

int save_public_key(const char *path, const public_key_t *key) {
    FILE *file = fopen(path, "w");
    if (!file) return -1;
    gmp_fprintf(file, "%Zx\n%Zx\n", key->n, key->e);
    fclose(file);
    return 0;
}

int save_private_key(const char *path, const private_key_t *key) {
    FILE *file = fopen(path, "w");
    if (!file) return -1;
    gmp_fprintf(file, "%Zx\n%Zx\n", key->n, key->d);
    fclose(file);
    return 0;
}

int load_public_key(const char *path, public_key_t *key) {
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    if (gmp_fscanf(file, "%Zx\n%Zx\n", key->n, key->e) != 2) {
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

int load_private_key(const char *path, private_key_t *key) {
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    if (gmp_fscanf(file, "%Zx\n%Zx\n", key->n, key->d) != 2) {
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}
