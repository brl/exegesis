

#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include "xbn_prime.h"
#include "../exegesis.h"
/* NB: these functions have been "upgraded", the deprecated versions (which are
 * compatibility wrappers using these functions) are in bn_depr.c.
 * - Geoff
 */

/* The quick sieve algorithm approach to weeding out primes is
 * Philip Zimmermann's, as implemented in PGP.  I have had a read of
 * his comments and implemented my own version.
 */

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont);

static int probable_prime(BIGNUM *rnd, int bits);

int xBN_generate_prime_ex(BIGNUM *ret, int bits)
	{
	BIGNUM *t;
	int found=0;
	int i,j,c1=0;
	BN_CTX *ctx;
	int checks = BN_prime_checks_for_size(bits);

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	t = BN_CTX_get(ctx);
	if(!t) goto err;
loop: 
	
	if (!probable_prime(ret,bits)) goto err;
	/* if (BN_mod_word(ret,(BN_ULONG)3) == 1) goto loop; */
	

	i=xBN_is_prime_fasttest_ex(ret,checks,ctx,0);
	if (i == -1) goto err;
	if (i == 0) goto loop;
		
	/* we have a prime :-) */
	found = 1;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	return found;
	}

static int probable_prime(BIGNUM *rnd, int bits)
	{
	int i;
	prime_t mods[NUMPRIMES];
	BN_ULONG delta,maxdelta;

again:
	if (!xBN_rand(rnd,bits,1,1)) return(0);
	/* we now have a random number 'rand' to test. */
	for (i=1; i<NUMPRIMES; i++)
		mods[i]=(prime_t)BN_mod_word(rnd,(BN_ULONG)primes[i]);
	maxdelta=BN_MASK2 - primes[NUMPRIMES-1];
	delta=0;
	loop: for (i=1; i<NUMPRIMES; i++)
		{
		/* check that rnd is not a prime and also
		 * that gcd(rnd-1,primes) == 1 (except for 2) */
		if (((mods[i]+delta)%primes[i]) <= 1)
			{
			delta+=2;
			if (delta > maxdelta) goto again;
			goto loop;
			}
		}
	if (!BN_add_word(rnd,delta)) return(0);
	return(1);
}
int xBN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
		int do_trial_division)
	{
	int i, j, ret = -1;
	int k;
	BN_CTX *ctx = NULL;
	BIGNUM *A1, *A1_odd, *check; /* taken from ctx */
	BN_MONT_CTX *mont = NULL;
	const BIGNUM *A = NULL;

	if (BN_cmp(a, BN_value_one()) <= 0)
		return 0;
	
	if (checks == BN_prime_checks)
		checks = BN_prime_checks_for_size(BN_num_bits(a));

	/* first look for small factors */
	if (!BN_is_odd(a))
		/* a is even => a is prime if and only if a == 2 */
		return BN_is_word(a, 2);
	if (do_trial_division)
		{
		for (i = 1; i < NUMPRIMES; i++)
			if (BN_mod_word(a, primes[i]) == 0) 
				return 0;
#if 0
		if(!BN_GENCB_call(cb, 1, -1))
			goto err;
#endif
		}

	if (ctx_passed != NULL)
		ctx = ctx_passed;
	else
		if ((ctx=BN_CTX_new()) == NULL)
			goto err;
	BN_CTX_start(ctx);

	/* A := abs(a) */
	if (a->neg)
		{
		BIGNUM *t;
		if ((t = BN_CTX_get(ctx)) == NULL) goto err;
		BN_copy(t, a);
		t->neg = 0;
		A = t;
		}
	else
		A = a;
	A1 = BN_CTX_get(ctx);
	A1_odd = BN_CTX_get(ctx);
	check = BN_CTX_get(ctx);
	if (check == NULL) goto err;

	/* compute A1 := A - 1 */
	if (!BN_copy(A1, A))
		goto err;
	if (!BN_sub_word(A1, 1))
		goto err;
	if (BN_is_zero(A1))
		{
		ret = 0;
		goto err;
		}

	/* write  A1  as  A1_odd * 2^k */
	k = 1;
	while (!BN_is_bit_set(A1, k))
		k++;
	if (!BN_rshift(A1_odd, A1, k))
		goto err;

	/* Montgomery setup for computations mod A */
	mont = BN_MONT_CTX_new();
	if (mont == NULL)
		goto err;
	if (!BN_MONT_CTX_set(mont, A, ctx))
		goto err;

	for (i = 0; i < checks; i++)
		{
		if(!xBN_rand_range(check, A1))
		//if (!BN_pseudo_rand_range(check, A1))
			goto err;
		if (!BN_add_word(check, 1))
			goto err;
		/* now 1 <= check < A */

		j = witness(check, A, A1, A1_odd, k, ctx, mont);
		if (j == -1) goto err;
		if (j)
			{
			ret=0;
			goto err;
			}
#if 0 
		if(!BN_GENCB_call(cb, 1, i))
			goto err;
#endif
		}
	ret=1;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		if (ctx_passed == NULL)
			BN_CTX_free(ctx);
		}
	if (mont != NULL)
		BN_MONT_CTX_free(mont);

	return(ret);
	}

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont)
	{
	if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx, mont)) /* w := w^a1_odd mod a */
		return -1;
	if (BN_is_one(w))
		return 0; /* probably prime */
	if (BN_cmp(w, a1) == 0)
		return 0; /* w == -1 (mod a),  'a' is probably prime */
	while (--k)
		{
		if (!BN_mod_mul(w, w, w, a, ctx)) /* w := w^2 mod a */
			return -1;
		if (BN_is_one(w))
			return 1; /* 'a' is composite, otherwise a previous 'w' would
			           * have been == -1 (mod 'a') */
		if (BN_cmp(w, a1) == 0)
			return 0; /* w == -1 (mod a), 'a' is probably prime */
		}
	/* If we get here, 'w' is the (a-1)/2-th power of the original 'w',
	 * and it is neither -1 nor +1 -- so 'a' cannot be prime */
//	bn_check_top(w);
	return 1;
	}

