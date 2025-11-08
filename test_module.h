#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#define LIMIT_SECONDS 600  // default brute force time limit per key (seconds)

// Bulk generate key pairs for powers of two in [min_bits, max_bits]
void test_bulk_keys(int min_bits, int max_bits);

// Verify integrity: encrypt then decrypt file with given bits (or latest if bits<=0). Returns 0 on success.
int test_integrity(const char *file_path, int bits);

// Measure encryption/decryption speed across powers-of-two bit lengths in range.
void test_speed(const char *file_path, int min_bits, int max_bits);

// Attempt to brute force private key(s) for powers-of-two bit lengths in range using factoring of n.
// Stops attempt if longer than provided limit_seconds (if <=0 uses LIMIT_SECONDS).
void test_bruteforce(const char *sample_file, int min_bits, int max_bits, int limit_seconds);

#endif // TEST_MODULE_H
