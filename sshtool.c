#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <stdarg.h>
#include "xssh/buffer.h"
#include "xssh/cipher.h"
#include "xssh/key.h"
#include "xssh/kex.h"
#include <nids.h>

#define CR ((char)0x0D)
#define LF ((char)0x0A)
#define SSH_MSG_KEXINIT  20
static void tcp_callback(struct tcp_stream *tcp, void **param);
static int client_data(char *data, int length);
static int server_data(char *data, int length);
static int parse_banner(char *data, int length, char *buffer);
static int parse_record(unsigned char *data, int length);
static int parse_keyinit(unsigned char *data, int length) ;


char client_banner[255 + 1];
char server_banner[255 + 1];
int have_client_banner = 0;
int have_server_banner = 0;
int pending_client_record_size = 0;
int pending_server_record_size = 0;

int main() {
	nids_params.filename = "data/ssh_capture";
	if(!nids_init()) {
		fprintf(stderr, "Nids error: %s\n", nids_errbuf);
	}
	printf("hi\n");
	nids_register_tcp(tcp_callback);
	nids_run();
	printf("done\n");
}


static void tcp_callback(struct tcp_stream *tcp, void **param) {
	int bytes_consumed = 0;
	
	printf("click\n");
	if(tcp->nids_state == NIDS_JUST_EST) {
		printf("new connection!\n");
		tcp->client.collect = 1;
		tcp->server.collect = 1;
		return;
	}
	
	if(tcp->nids_state == NIDS_CLOSE) {
		printf("connection closed\n");
		return;
	}
	
	if(tcp->nids_state == NIDS_RESET) {
		printf("connection reset\n");
		return;
	}
	
	if(tcp->nids_state == NIDS_DATA) {
		if(tcp->client.count_new > 0) {
			bytes_consumed = client_data(tcp->client.data, tcp->client.count_new);
		} else if(tcp->server.count_new > 0) {
			bytes_consumed = server_data(tcp->server.data, tcp->server.count_new);
		}
		printf("discard: %d\n", bytes_consumed);
		nids_discard(tcp, bytes_consumed);
	}	
	
}

/*
 * returns number of bytes consumed
 */
static int client_data(char *data, int length) {
	int bytes_consumed = 0;
	printf("client data %d bytes\n", length);
	
	if(!have_client_banner) {
		if((bytes_consumed = parse_banner(data, length, client_banner)) > 0) {
			have_client_banner = 1;
			printf("client banner: %s\n", client_banner);
		}
		return bytes_consumed;
	}
	
	bytes_consumed = parse_record((unsigned char *)data, length);
	return bytes_consumed;
	
}
static int server_data(char *data, int length) {
	int bytes_consumed = 0;
	printf("server data %d bytes\n", length);
	if(!have_server_banner) {
		if((bytes_consumed = parse_banner(data, length, server_banner)) > 0) {
			have_server_banner = 1;
			printf("server banner: %s\n", server_banner);
		}
		return bytes_consumed;
	}
	
	bytes_consumed = parse_record((unsigned char *)data, length);
	return bytes_consumed;
}

static int parse_banner(char *data, int length, char *buffer) {
	int search_length;
	int banner_length;
	int consumed;
	char *p;
	
	// XXX process optional data before version string
	
	search_length = (length > 255) ? (255) : length;
	
	p = memchr(data, LF, search_length);
	
	if(!p) {
		if(length >= 255) {
			fprintf(stderr, "Banner not found!\n");
			exit(1);
		}
		return 0;
	}
	consumed = (p - data) + 1;
	if(p == data) {
		fprintf(stderr, "Illegal banner\n");
		exit(1);
	}
	
	if(*(p-1) == CR) 
		p--;	
	
	banner_length = p - data;
	memcpy(buffer, data, banner_length);
	buffer[banner_length] = 0;
	return consumed;
}

static int parse_record(unsigned char *data, int length) {
	unsigned record_length = 0;
	
	record_length |= data[0] << 24;
	record_length |= data[1] << 16;
	record_length |= data[2] << 8;
	record_length |= data[3];
	if(length < (record_length + 4)) {
		printf("not enough, need %d\n", record_length + 4);
		return 0;
	}

	printf("record length is %d\n", record_length);
	printf("padding length is %d\n", data[4]);
	printf("message type is %d\n", data[5]);
	if(data[5] == SSH_MSG_KEXINIT) {
		parse_keyinit(data + 6, record_length - (data[4]) - 2);
	}
	return record_length + 4;

}

static int parse_keyinit(unsigned char *data, int length) {
	u_char cookie[16];
	char *proposal[PROPOSAL_MAX];
	int i;
	int first_kex_follows= 0;
	int reserved = 0;
	Buffer b;
	buffer_init(&b);
	buffer_append(&b, data, length);
	printf("cookie: ");
	for(i = 0; i < 16; i++) {
		cookie[i] = buffer_get_char(&b);
		printf("%.2X", cookie[i]);
	}
	printf("\n");
	
	for(i = 0; i < PROPOSAL_MAX; i++) {
		proposal[i] = buffer_get_string(&b, NULL);
		printf("proposal: %s\n", proposal[i]);
	}
	// XXX not supported
	first_kex_follows = buffer_get_char(&b);
	reserved = buffer_get_int(&b);
	
	
	
	
}
