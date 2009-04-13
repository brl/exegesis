#define HASH    EVP_sha1()

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "../exegesis.h"


DSA *xDSA_generate_parameters(int bits) {
	DSA *dsa = DSA_new();
	if(xDSA_paramgen(dsa, bits) != 0) {
		return dsa;
	}
	DSA_free(dsa);
	return NULL;
	
}

int xDSA_paramgen(DSA *ret, int bits)

{
	int ok=0;
	unsigned char seed[SHA_DIGEST_LENGTH];
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char buf[SHA_DIGEST_LENGTH], buf2[SHA_DIGEST_LENGTH];
	BIGNUM *r0, *W, *X, *c, *test;
	BIGNUM *g=NULL, *q=NULL, *p=NULL;
	BN_MONT_CTX *mont=NULL;
	int k, n=0, i, b;
	int counter=0;
	int r=0;
	BN_CTX *ctx=NULL;
	unsigned int h=2;

	if (bits < 512)
		bits=512;
	bits=(bits+63)/64*64;



	if ((ctx=BN_CTX_new()) == NULL)
		goto err;

	if ((mont=BN_MONT_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	g = BN_CTX_get(ctx);
	W = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	c = BN_CTX_get(ctx);
	p = BN_CTX_get(ctx);
	test = BN_CTX_get(ctx);

	if (!BN_lshift(test, BN_value_one(), bits-1))
		goto err;

	for (;;) {
		for (;;) /* find q */
		{
			int seed_is_random;
			/* step 1 */
			xRAND_bytes(seed, SHA_DIGEST_LENGTH);
			seed_is_random = 1;

			memcpy(buf, seed, SHA_DIGEST_LENGTH);
			memcpy(buf2, seed, SHA_DIGEST_LENGTH);
			/* precompute "SEED + 1" for step 7: */
			for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--) {
				buf[i]++;
				if (buf[i] != 0)
					break;
			}
			/* step 2 */
			EVP_Digest(seed, SHA_DIGEST_LENGTH, md, NULL, HASH, NULL);
			EVP_Digest(buf, SHA_DIGEST_LENGTH, buf2, NULL, HASH, NULL);
			for (i=0; i<SHA_DIGEST_LENGTH; i++)
				md[i]^=buf2[i];
			/* step 3 */
			md[0]|=0x80;
			md[SHA_DIGEST_LENGTH-1]|=0x01;
			if (!BN_bin2bn(md, SHA_DIGEST_LENGTH, q))
				goto err;
			/* step 4 */
			r = xBN_is_prime_fasttest_ex(q, DSS_prime_checks, ctx,
					seed_is_random);
			if (r > 0)
				break;
			if (r != 0)
				goto err;
			/* do a callback call */
			/* step 5 */
		}

		/* step 6 */
		counter=0;
		/* "offset = 2" */

		n=(bits-1)/160;
		b=(bits-1)-n*160;

		for (;;) {

			/* step 7 */
			BN_zero(W);
			/* now 'buf' contains "SEED + offset - 1" */
			for (k=0; k<=n; k++) {
				/* obtain "SEED + offset + k" by incrementing: */
				for (i=SHA_DIGEST_LENGTH-1; i >= 0; i--) {
					buf[i]++;
					if (buf[i] != 0)
						break;
				}

				EVP_Digest(buf, SHA_DIGEST_LENGTH, md, NULL, HASH, NULL);
				/* step 8 */
				if (!BN_bin2bn(md, SHA_DIGEST_LENGTH, r0))
					goto err;
				if (!BN_lshift(r0, r0, 160*k))
					goto err;
				if (!BN_add(W, W, r0))
					goto err;
			}

			/* more of step 8 */
			if (!BN_mask_bits(W, bits-1))
				goto err;
			if (!BN_copy(X, W))
				goto err;
			if (!BN_add(X, X, test))
				goto err;
			/* step 9 */
			if (!BN_lshift1(r0, q))
				goto err;
			if (!BN_mod(c,X,r0,ctx))
				goto err;
			if (!BN_sub(r0, c, BN_value_one()))
				goto err;
			if (!BN_sub(p, X, r0))
				goto err;
			/* step 10 */
			if (BN_cmp(p, test) >= 0) {
				/* step 11 */
				
				r = xBN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1);
				if (r > 0)
					goto end;
				/* found it */
				if (r != 0)
					goto err;
			}
			/* step 13 */
			counter++;
			/* "offset = offset + n + 1" */
			
			/* step 14 */
			if (counter >= 4096)
				break;
		}
	}
end: 
	
	/* We now need to generate g */
	/* Set r0=(p-1)/q */
	if (!BN_sub(test, p, BN_value_one()))
		goto err;
	if (!BN_div(r0, NULL, test, q, ctx))
		goto err;

	if (!BN_set_word(test, h))
		goto err;
	if (!BN_MONT_CTX_set(mont, p, ctx))
		goto err;

	for (;;) {
		/* g=test^r0%p */
		if (!BN_mod_exp_mont(g, test, r0, p, ctx, mont))
			goto err;
		if (!BN_is_one(g))
			break;
		if (!BN_add(test, test, BN_value_one()))
			goto err;
		h++;
	}


	ok=1;
	err:
	if (ok) {
		if (ret->p)
			BN_free(ret->p);
		if (ret->q)
			BN_free(ret->q);
		if (ret->g)
			BN_free(ret->g);
		ret->p=BN_dup(p);
		ret->q=BN_dup(q);
		ret->g=BN_dup(g);
		if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
			ok=0;
			goto err;
		}

	}
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (mont != NULL)
		BN_MONT_CTX_free(mont);
	return ok;
}

int xDSA_keygen(DSA *dsa) {
	int ok=0;
	BN_CTX *ctx=NULL;
	BIGNUM *pub_key=NULL, *priv_key=NULL;

	if ((ctx=BN_CTX_new()) == NULL)
		goto err;

	if (dsa->priv_key == NULL) {
		if ((priv_key=BN_new()) == NULL)
			goto err;
	} else
		priv_key=dsa->priv_key;

	do
		if (!xBN_rand_range(priv_key, dsa->q))
			goto err;
	while (BN_is_zero(priv_key));

	if (dsa->pub_key == NULL) {
		if ((pub_key=BN_new()) == NULL)
			goto err;
	} else
		pub_key=dsa->pub_key;

	{
		BIGNUM *prk;

			prk = priv_key;

		if (!BN_mod_exp(pub_key, dsa->g, prk, dsa->p, ctx))
			goto err;
	}

	dsa->priv_key=priv_key;
	dsa->pub_key=pub_key;
	ok=1;

	err: if ((pub_key != NULL) && (dsa->pub_key == NULL))
		BN_free(pub_key);
	if ((priv_key != NULL) && (dsa->priv_key == NULL))
		BN_free(priv_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
	return (ok);
}
