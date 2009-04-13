#include <stdio.h>
#include <string.h>
#include "../exegesis.h"
#include <openssl/evp.h>
#define MD_Update(a,b,c)	EVP_DigestUpdate(a,b,c)
#define	MD_Final(a,b)		EVP_DigestFinal_ex(a,b,NULL)
#include <openssl/sha.h>
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#define MD_Init(a)		EVP_DigestInit_ex(a,EVP_sha1(), NULL)
#define	MD(a,b,c)		EVP_Digest(a,b,c,NULL,EVP_sha1(), NULL)

#define ENTROPY_NEEDED 32  /* require 256 bits = 32 bytes of randomness */

#define STATE_SIZE	1023
static int state_num=0, state_index=0;
static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];
static unsigned char md[MD_DIGEST_LENGTH];
static long md_count[2]= { 0, 0 };
static double entropy=0;
static int stirred_pool = 0;
static int target_long_size = 4;
static unsigned char pid_bytes[4];
static target_bits mode_bits;
static target_endian mode_endian;
static int xRAND_poll(void);
static void xRAND_setup_pid(int pid, target_endian endian);


void xRAND_init(int pid, target_bits bits, target_endian endian) {
	memset(state, 0, sizeof(state));
	state_num=0;
	state_index=0;
	memset(md, 0, MD_DIGEST_LENGTH);
	md_count[0]=0;
	md_count[1]=0;
	entropy=0;
	stirred_pool = 0;

	switch(bits) {
	case TARGET_BITS_32:
		target_long_size = 4;
		break;
	case TARGET_BITS_64:
		target_long_size = 8;
		break;
	default:
		break;
		
	}
	
	mode_bits = bits;
	mode_endian = endian;
	xRAND_setup_pid(pid, endian);
	xRAND_poll();

}

static void xRAND_setup_pid(int pid, target_endian endian) {
	if (endian == TARGET_BIG_ENDIAN) {
		pid_bytes[0] = (unsigned char) (pid >> 24);
		pid_bytes[1] = (unsigned char) (pid >> 16);
		pid_bytes[2] = (unsigned char) (pid >> 8);
		pid_bytes[3] = (unsigned char) (pid);
	} else {
		pid_bytes[3] = (unsigned char) (pid >> 24);
		pid_bytes[2] = (unsigned char) (pid >> 16);
		pid_bytes[1] = (unsigned char) (pid >> 8);
		pid_bytes[0] = (unsigned char) (pid);
	}

}

/*
 * buffer must be at least target_long_size in length
 */
static void pack(long n, unsigned char *buffer) {
	unsigned char *p;
	memset(buffer, 0, target_long_size);
	p = buffer;
	
	/*
	 * n = ABCD
	 * 
	 * 32 bit little endian
	 * DCBA....
	 * 
	 * 64 bit little endian
	 * DCBA0000
	 * 
	 * 32 bit big endian
	 * ABCD....
	 * 
	 * 64 bit big endian
	 * 0000ABCD
	 */
	if(mode_bits == TARGET_BITS_64 && mode_endian == TARGET_BIG_ENDIAN) {
		p += 4;
	} 
	
	if(mode_endian == TARGET_BIG_ENDIAN) {
		p[0] = (unsigned char) (n >> 24);
		p[1] = (unsigned char) (n >> 16);
		p[2] = (unsigned char) (n >> 8);
		p[3] = (unsigned char) (n);
	} else {
		p[3] = (unsigned char) (n >> 24);
		p[2] = (unsigned char) (n >> 16);
		p[1] = (unsigned char) (n >> 8);
		p[0] = (unsigned char) (n);
	}
	

}

static char *md_c_buffer(long md_c[2]) {
	static unsigned char b[16];
	unsigned char *p = b;
	pack(md_c[0], p);
	p += target_long_size;
	pack(md_c[1], p);
	return b;
}

static int xRAND_poll(void) {

	// /dev/urandom
	xRAND_add(ENTROPY_NEEDED);
	// getpid();
	xRAND_add_long();
	// getuid();
	xRAND_add_long();
	// time();
	xRAND_add_long();
	return 1;
}

void xRAND_add_long() {
	xRAND_add(target_long_size);
}


void xRAND_add(int num) {
	int i, j, k, st_idx;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX m;


	st_idx=state_index;

	md_c[0] =  md_count[0];
	md_c[1] =  md_count[1];

	memcpy(local_md, md, sizeof md);

	/* state_index <= state_num <= STATE_SIZE */
	state_index += num;
	if (state_index >= STATE_SIZE) {
		state_index%=STATE_SIZE;
		state_num=STATE_SIZE;
	} else if (state_num < STATE_SIZE) {
		if (state_index > state_num)
			state_num=state_index;
	}

	md_count[1] += (num / MD_DIGEST_LENGTH) + (num % MD_DIGEST_LENGTH > 0);

	EVP_MD_CTX_init(&m);
	for (i=0; i<num; i+=MD_DIGEST_LENGTH) {
		j=(num-i);
		j=(j > MD_DIGEST_LENGTH) ? MD_DIGEST_LENGTH : j;

		MD_Init(&m);
		MD_Update(&m, local_md, MD_DIGEST_LENGTH);
		k=(st_idx+j)-STATE_SIZE;
		if (k > 0) {
			MD_Update(&m, &(state[st_idx]), j-k);
			MD_Update(&m, &(state[0]), k);
		} else
			MD_Update(&m, &(state[st_idx]), j);

		/*
		 MD_Update(&m,buf,j);
		 */
		//MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c));
		MD_Update(&m, md_c_buffer(md_c), target_long_size * 2);
		MD_Final(&m, local_md);
		md_c[1]++;

		//	buf=(const char *)buf + j;

		for (k=0; k<j; k++) {
			state[st_idx++]^=local_md[k];
			if (st_idx >= STATE_SIZE)
				st_idx=0;
		}
	}
	EVP_MD_CTX_cleanup(&m);

	for (k = 0; k < (int)sizeof(md); k++) {
		md[k] ^= local_md[k];
	}

}



int xRAND_bytes(unsigned char *buf, int num) {
	int i, j, k, st_num, st_idx;
	int num_ceil;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX m;
	int pid_flag = 1;
	int do_stir_pool = 0;

	if (num <= 0)
		return 1;

	EVP_MD_CTX_init(&m);
	/* round upwards to multiple of MD_DIGEST_LENGTH/2 */
	num_ceil = (1 + (num-1)/(MD_DIGEST_LENGTH/2)) * (MD_DIGEST_LENGTH/2);

	if (!stirred_pool)
		do_stir_pool = 1;

	if (do_stir_pool) {
		int n= STATE_SIZE; /* so that the complete pool gets accessed */
		while (n > 0) {

			xRAND_add(MD_DIGEST_LENGTH);
			n -= MD_DIGEST_LENGTH;
		}
		stirred_pool = 1;
	}

	st_idx=state_index;
	st_num=state_num;
	md_c[0] = md_count[0];
	md_c[1] = md_count[1];
	memcpy(local_md, md, sizeof md);

	state_index+=num_ceil;
	if (state_index > state_num)
		state_index %= state_num;

	md_count[0] += 1;

	while (num > 0) {
		/* num_ceil -= MD_DIGEST_LENGTH/2 */
		j=(num >= MD_DIGEST_LENGTH/2) ? MD_DIGEST_LENGTH/2 : num;
		num-=j;
		MD_Init(&m);

		if (pid_flag) /* just in the first iteration to save time */
		{

			MD_Update(&m, pid_bytes, sizeof(pid_bytes));
			pid_flag = 0;
		}

		MD_Update(&m, local_md, MD_DIGEST_LENGTH);
		//MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c));
		MD_Update(&m, md_c_buffer(md_c), target_long_size * 2);


		/*
		 MD_Update(&m,buf,j); 
		 */
		k=(st_idx+MD_DIGEST_LENGTH/2)-st_num;
		if (k > 0) {
			MD_Update(&m, &(state[st_idx]), MD_DIGEST_LENGTH/2-k);
			MD_Update(&m, &(state[0]), k);
		} else
			MD_Update(&m, &(state[st_idx]), MD_DIGEST_LENGTH/2);
		MD_Final(&m, local_md);

		for (i=0; i<MD_DIGEST_LENGTH/2; i++) {
			state[st_idx++]^=local_md[i]; /* may compete with other threads */
			if (st_idx >= st_num)
				st_idx=0;
			if (i < j)
				*(buf++)=local_md[i+MD_DIGEST_LENGTH/2];
		}
	}

	MD_Init(&m);
	//MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c));
	MD_Update(&m, md_c_buffer(md_c), target_long_size * 2);
	MD_Update(&m, local_md, MD_DIGEST_LENGTH);
	MD_Update(&m, md, MD_DIGEST_LENGTH);
	MD_Final(&m, md);

	EVP_MD_CTX_cleanup(&m);
	return 1;

}

