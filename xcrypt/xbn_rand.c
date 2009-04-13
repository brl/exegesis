#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "../exegesis.h"

int xBN_rand(BIGNUM *rnd, int bits, int top, int bottom) {
	unsigned char *buf=NULL;
	int ret=0, bit, bytes, mask;

	if (bits == 0) {
		BN_zero(rnd);
		return 1;
	}

	bytes=(bits+7)/8;
	bit=(bits-1)%8;
	mask=0xff<<(bit+1);

	buf= malloc(bytes);

	/* make a random number and set the top and bottom bits */
	xRAND_add_long();

	if (xRAND_bytes(buf, bytes) <= 0) {
		goto err;
	}

	if (top != -1) {
		if (top) {
			if (bit == 0) {
				buf[0]=1;
				buf[1]|=0x80;
			} else {
				buf[0]|=(3<<(bit-1));
			}
		} else {
			buf[0]|=(1<<bit);
		}
	}
	buf[0] &= ~mask;
	if (bottom) /* set bottom bit if requested */
		buf[bytes-1]|=1;
	if (!BN_bin2bn(buf, bytes, rnd))
		goto err;
	ret=1;
	err: if (buf != NULL) {
		free(buf);

	}
	return (ret);
}


/* random number r:  0 <= r < range */
int xBN_rand_range(BIGNUM *r, BIGNUM *range) {
	int n;
	int count = 100;

	n = BN_num_bits(range); /* n > 0 */

	/* BN_is_bit_set(range, n - 1) always holds */

	if (n == 1)
		BN_zero(r);
	else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
		/* range = 100..._2,
		 * so  3*range (= 11..._2)  is exactly one bit longer than  range */
		do {
			if (!xBN_rand(r, n + 1, -1, 0))
				return 0;
			/* If  r < 3*range,  use  r := r MOD range
			 * (which is either  r, r - range,  or  r - 2*range).
			 * Otherwise, iterate once more.
			 * Since  3*range = 11..._2, each iteration succeeds with
			 * probability >= .75. */
			if (BN_cmp(r, range) >= 0) {
				if (!BN_sub(r, r, range))
					return 0;
				if (BN_cmp(r, range) >= 0)
					if (!BN_sub(r, r, range))
						return 0;
			}

			if (!--count) {
				return 0;
			}

		} while (BN_cmp(r, range) >= 0);
	} else {
		do {
			/* range = 11..._2  or  range = 101..._2 */
			if (!xBN_rand(r, n, -1, 0))
				return 0;

			if (!--count) {
				return 0;
			}
		} while (BN_cmp(r, range) >= 0);
	}

	return 1;
}

