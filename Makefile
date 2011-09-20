CC=gcc
MY_APXS=/usr/local/apache2/bin/apxs

MY_LDFLAGS=-lcurl -lyajl
MY_CFLAGS=

.SUFFIXES: .c .o .la
.c.la:
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $< 
.c.o:
	$(CC) -c $<

all:  mod_auth_browserid.la 

install: mod_auth_browserid.la 
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	$(MY_APXS) -i $?

clean:
	-rm -f *.o *.lo *.la *.slo 
	-rm -rf .libs

