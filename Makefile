
EXEGESIS_OBJS=exegesis.o
SSHTOOL_OBJS=sshtool.o
INCLUDED_KEYSETS=keysets
all: $(EXEGESIS_OBJS) exegesis 
install: all
	install -d $(DESTDIR)/usr/share/exegesis/
	install exegesis $(DESTDIR)/usr/bin/
	cp -r $(INCLUDED_KEYSETS) $(DESTDIR)/usr/share/exegesis/

LD=gcc
LIBS=-lcrypto
CFLAGS=-I/opt/local/include
SSHTOOL_LIBS=-L/opt/local/lib -lnids -lpcap -lnet -lxssh
LD_FLAGS=-Lxssh -Lxcrypt
LIBXSSH=xssh/libxssh.a
$(LIBXSSH): 
	(cd xssh && $(MAKE))
	
LIBXCRYPT=xcrypt/libxcrypt.a
$(LIBXCRYPT): 
	(cd xcrypt && $(MAKE))

always:

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
	
exegesis: $(LIBXCRYPT) $(LIBXSSH) $(EXEGESIS_OBJS)
	$(LD) -o $@ $(EXEGESIS_OBJS) $(LD_FLAGS) -lxssh -lxcrypt $(LIBS)
	
sshtool: $(LIBXSSH) $(SSHTOOL_OBJS)
	$(LD) -o $@ $(SSHTOOL_OBJS) $(LD_FLAGS) $(SSHTOOL_LIBS)
	
clean:
	rm -f *.o exegesis
	(cd xcrypt && $(MAKE) clean)
	(cd xssh && $(MAKE) clean)
