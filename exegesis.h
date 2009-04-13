#ifndef EXEGESIS_H_
#define EXEGESIS_H_
typedef enum {
	TARGET_BIG_ENDIAN,
	TARGET_LITTLE_ENDIAN
} target_endian;

typedef enum {
	TARGET_BITS_32,
	TARGET_BITS_64
} target_bits;
#include <openssl/dsa.h>
#include <openssl/rsa.h>
void xRAND_init(int pid, target_bits bits, target_endian endian);
void xRAND_add(int num);
int xRAND_bytes(unsigned char *buf, int num);
void xRAND_add_long();
 
int xBN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int xBN_rand_range(BIGNUM *r, BIGNUM *range);


int xDSA_keygen(DSA *dsa);
int xDSA_paramgen(DSA *ret, int bits);
DSA *xDSA_generate_parameters(int bits);

RSA *xRSA_generate_key(int bits, unsigned long e_value);

int xBN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
		int do_trial_division);

#endif 
