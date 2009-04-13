LIBXSSH=base64.o bufaux.o bufbn.o buffer.o key.o misc.o uuencode.o xmalloc.o match.o
AR=/usr/bin/ar
RANLIB=ranlib

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: libxssh.a
libxssh.a: $(LIBXSSH)
	$(AR) rv $@ $(LIBXSSH)
	$(RANLIB) $@

clean:
	rm -f *.o *.a 
