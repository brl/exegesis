#ifndef SSHTOOL_H_
#define SSHTOOL_H_
#include <openssl/evp.h>
#include "xssh/cipher.h"
#include "xssh/key.h"
struct ssh_half {
	char *banner;
	Enc *enc;
	Mac *mac;
	Comp *comp;
};
struct ssh_state {
	
};
#endif /*SSHTOOL_H_*/
