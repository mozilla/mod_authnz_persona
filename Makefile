CC=gcc
ifeq ($(APXS_PATH),)
APXS_PATH=/usr/sbin/apxs
endif

MY_LDFLAGS=-lcurl -lyajl

# Note that gcc flags are passed through apxs, so preface with -Wc
MY_CFLAGS=-Wc,-I. -Wc,-Wall

.SUFFIXES: .c .o .la
.c.la:
	$(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $<
.c.o:
	$(CC) -c $<

all:  mod_auth_browserid.la

install: mod_auth_browserid.la
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	$(APXS_PATH) -i $?

clean:
	-rm -f *.o *.lo *.la *.slo
	-rm -rf .libs

