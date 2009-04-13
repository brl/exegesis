#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include "xssh/key.h"
#include "exegesis.h"

#define MAXIMUM_PID  0xFFFF

static Key *generate_key();
static int save_private_key(FILE *fp, Key *key);
static int generate_keyset();
static void range_parse(char *range);

static void usage(char *name) {
	fprintf(stderr, "Usage: %s [options]\n", name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -B            Select big endian target (default is little endian target).\n");
	fprintf(stderr, "  -A            Selecet 64 bit target (default is 32 bit target)\n");
	fprintf(stderr, "  -o <file>     Output file.\n");
	fprintf(stderr, "  -t (dsa|rsa)  Type of key(s) to generate (default is rsa)\n");
	fprintf(stderr, "  -b bits       Key size to generate in bits (default is 1024 bits)\n");
	fprintf(stderr, "  -g            Generate all keys for a range of pids (all pids by default)\n");
	fprintf(stderr, "  -r start,end  Specify a pid range to generate (default is 1,32768)\n");
	fprintf(stderr, "  -p pid        Generate a key for a chosen pid value\n");
	exit(1);
}

/* 
 * Default configuration
 */
target_bits      config_target_bits           = TARGET_BITS_32;
target_endian    config_target_endian         = TARGET_LITTLE_ENDIAN;
enum types       config_key_type              = KEY_RSA;
int              config_key_bits              = 1024;
char *           config_outfile               = NULL;
int              config_range_start           = 1;
int              config_range_end             = 32768;

FILE *			 output_fp = NULL;

int main(int argc, char **argv) {

	int opt;
	extern int optind;
	extern char *optarg;
	FILE *open_fp = NULL;
	char *key_type_name = NULL;
	int bits = 0;
	int generate_flag = 0;
	int pid = 0;
	char *range_string = NULL;
	Key *key;
	
	output_fp = stdout;

	if(argc < 2) {
		usage(argv[0]);
	}

	while((opt = getopt(argc, argv, "BAo:t:b:gr:p:")) != -1) {
		switch(opt) {
		case 'B':
			config_target_endian = TARGET_BIG_ENDIAN;
			break;
			
		case 'A':
			config_target_bits = TARGET_BITS_64;
			break;
			
		case 'o':
			config_outfile = optarg;
			break;
			
		case 't':
			key_type_name = optarg;
			break;
			
		case 'b':
			config_key_bits = atoi(optarg);
			break;
			
		case 'g':
			generate_flag = 1;
			break;
			
		case 'r':
			range_parse(optarg);
			break;
			
		case 'p':
			pid = atoi(optarg);
			if(pid < 1 || pid > MAXIMUM_PID) {
				fprintf(stderr, "Illegal pid value %d\n", pid);
				exit(1);
			}
			break;
			
		case '?':
		default:
			usage(argv[0]);		
		}
		
	}
	
	if(!generate_flag && pid == 0) {
		fprintf(stderr, "At least one of options -p or -g must be specified\n");
		exit(1);
	}
	if(generate_flag && pid != 0) {
		fprintf(stderr, "Options -p and -g cannot be used together.\n");
		exit(1);
	}
	
	if(key_type_name != NULL) {
		if(strcmp(key_type_name, "dsa") == 0) {
			config_key_type = KEY_DSA;
		} else if(strcmp(key_type_name, "rsa") == 0) {
			config_key_type = KEY_RSA;
		} else {
			fprintf(stderr, "Illegal key type '%s'\n", key_type_name);
			exit(1);
		}
	}
	if(config_outfile != NULL) {
		open_fp = fopen(config_outfile, "w");
		if(!open_fp) {
			fprintf(stderr, "Could not open file '%s' for writing.\n", config_outfile);
		}
		output_fp = open_fp;
	}

	
	if(generate_flag) {
		generate_keyset();
		if(open_fp) {
			fclose(open_fp);
		}
		exit(0);
	}
	
	key = generate_key(pid);
	save_private_key(output_fp, key);
	

}
static void range_parse(char *range) {
	char *p;
	int start;
	int end;
	
	p = strchr(range, ',');
	if(p == NULL || *(p + 1) == 0) goto err;
	*p = 0;
	start = atoi(range);
	end = atoi(p + 1);
	*p = '-';
	
	if(start < 0 || start > MAXIMUM_PID || start > end)
		goto err;
	
	if(end < 0 || end > MAXIMUM_PID)
		goto err;
	
	config_range_start = start;
	config_range_end = end;
	return;
	
	
err:
	fprintf(stderr, "Failed to parse range '%s'\n", range);
	exit(1);
}

static Key *
generate_key(int pid) {
	unsigned char buf[20];

	xRAND_init(pid, config_target_bits, config_target_endian);
	xRAND_bytes(buf, 20);
	return key_generate(config_key_type, config_key_bits);
}

static int 
save_private_key(FILE *fp, Key *key) {
	int ok;
	switch(key->type) {
	case KEY_DSA:
		ok = PEM_write_DSAPrivateKey(fp, key->dsa, NULL, NULL, 0, NULL, NULL);
		break;
	case KEY_RSA:
		ok = PEM_write_RSAPrivateKey(fp, key->rsa, NULL, NULL, 0, NULL, NULL);
		break;
	}
	return ok;
}

static int generate_keyset() {
	int pid;
	Key *key;
	int endian_flag;
	int bits_value;
	char *key_type_string;
	

	
	switch(config_target_bits) {
	case TARGET_BITS_32:
		bits_value = 32;
		break;
	case TARGET_BITS_64:
		bits_value = 64;
		break;
	default:
		fprintf(stderr, "config_target_bits has illegal value.\n");
		exit(1);
	}
	
	switch(config_target_endian) {
	case TARGET_LITTLE_ENDIAN:
		endian_flag = 0;
		break;
	case TARGET_BIG_ENDIAN:
		endian_flag = 1;
		break;
	default:
		fprintf(stderr, "config_target_endian has illegal value.\n");
		exit(1);
	}
	
	switch(config_key_type) {
	case KEY_RSA:
		key_type_string = "rsa";
		break;
	case KEY_DSA:
		key_type_string = "dsa";
		break;
	default:
		fprintf(stderr, "config_key_type has illegal value.\n");
		exit(1);
	}

	for(pid = config_range_start; pid <= config_range_end; pid++) {
		key = generate_key(pid);
		fprintf(output_fp, "%s %u %s %u %u %u\n", key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX), pid, key_type_string, config_key_bits, bits_value, endian_flag);
		fflush(output_fp);
	}
}
