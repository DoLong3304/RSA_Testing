#include <stdio.h>
#include "rsa.h"
#include <stdlib.h>
#include <time.h>

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

static void generate_prime(mpz_t prime, unsigned int bits, gmp_randstate_t rand_state) {
    do {
        mpz_urandomb(prime, rand_state, bits);
        mpz_nextprime(prime, prime);
    } while (mpz_sizeinbase(prime, 2) != bits);
}

void generate_keys(public_key_t *pub, private_key_t *priv, unsigned int bit_length) {
    mpz_t p, q, phi;
    mpz_inits(p, q, phi, NULL);
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    unsigned int prime_bits = bit_length / 2;
    generate_prime(p, prime_bits, rand_state);
    do {
        generate_prime(q, prime_bits, rand_state);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(pub->n, p, q);
    mpz_set(priv->n, pub->n);

    mpz_t p_minus_1, q_minus_1;
    mpz_inits(p_minus_1, q_minus_1, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);

    mpz_set_ui(pub->e, 65537);

    if (mpz_invert(priv->d, pub->e, phi) == 0) {
        fprintf(stderr, "Error: Modular inverse does not exist. Key generation failed.\n");
        exit(1);
    }

    mpz_clears(p, q, phi, p_minus_1, q_minus_1, NULL);
    gmp_randclear(rand_state);
}

int encrypt_file(const char *input_path, const char *output_path, const public_key_t *pub) {
    FILE *in_file = fopen(input_path, "rb");
    if (!in_file) {
        perror("Error opening input file for encryption");
        return -1;
    }

    FILE *out_file = fopen(output_path, "w");
    if (!out_file) {
        perror("Error opening output file for encryption");
        fclose(in_file);
        return -1;
    }

    size_t key_bytes = (mpz_sizeinbase(pub->n, 2) + 7) / 8;
    size_t chunk_size = key_bytes - 1;
    unsigned char *buffer = malloc(chunk_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(in_file);
        fclose(out_file);
        return -1;
    }

    mpz_t m, c;
    mpz_inits(m, c, NULL);

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, chunk_size, in_file)) > 0) {
        mpz_import(m, bytes_read, 1, sizeof(unsigned char), 0, 0, buffer);
        mpz_powm(c, m, pub->e, pub->n);
        gmp_fprintf(out_file, "%Zx\n", c);
    }

    mpz_clears(m, c, NULL);
    free(buffer);
    fclose(in_file);
    fclose(out_file);
    return 0;
}

int decrypt_file(const char *input_path, const char *output_path, const private_key_t *priv) {
    FILE *in_file = fopen(input_path, "r");
    if (!in_file) {
        perror("Error opening input file for decryption");
        return -1;
    }

    FILE *out_file = fopen(output_path, "wb");
    if (!out_file) {
        perror("Error opening output file for decryption");
        fclose(in_file);
        return -1;
    }

    mpz_t c, m;
    mpz_inits(c, m, NULL);

    while (gmp_fscanf(in_file, "%Zx\n", c) == 1) {
        mpz_powm(m, c, priv->d, priv->n);
        size_t size;
        unsigned char *buffer = mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, m);
        fwrite(buffer, 1, size, out_file);
        free(buffer);
    }

    mpz_clears(c, m, NULL);
    fclose(in_file);
    fclose(out_file);
    return 0;
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

