#ifndef RSA_H
#define RSA_H

#include <gmp.h>

// Structure for the RSA public key (n, e)
typedef struct {
    mpz_t n; // modulus
    mpz_t e; // public exponent
} public_key_t;

// Structure for the RSA private key (n, d)
typedef struct {
    mpz_t n; // modulus
    mpz_t d; // private exponent
} private_key_t;

void generate_keys(public_key_t *pub, private_key_t *priv, unsigned int bit_length);

int encrypt_file(const char *input_path, const char *output_path, const public_key_t *pub);

int decrypt_file(const char *input_path, const char *output_path, const private_key_t *priv);

int save_public_key(const char *path, const public_key_t *key);

int save_private_key(const char *path, const private_key_t *key);

int load_public_key(const char *path, public_key_t *key);

int load_private_key(const char *path, private_key_t *key);

void init_public_key(public_key_t *key);

void init_private_key(private_key_t *key);

void clear_public_key(public_key_t *key);

void clear_private_key(private_key_t *key);

#endif // RSA_H
