LIBXCRYPTO=xbn_prime.o xbn_rand.o xdsa_gen.o xrand.o xrsa_gen.o
AR=/usr/bin/ar
RANLIB=ranlib

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: libxcrypt.a
libxcrypt.a: $(LIBXCRYPTO)
	$(AR) rv $@ $(LIBXCRYPTO)
	$(RANLIB) $@

clean:
	rm -f *.o *.a 

