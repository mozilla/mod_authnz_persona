ifeq ($(APXS_PATH),)
APXS_PATH=/usr/sbin/apxs
endif

MY_LDFLAGS=-lcurl -lyajl
# Note that gcc flags are passed through apxs, so preface with -Wc
MY_CFLAGS=-Wc,-I. -Wc,-Wall -Wc,-g
SRCS=src/mod_auth_browserid.c src/cookie.c
HDRS=src/cookie.h src/defines.h src/config.h

.SUFFIXES: .c .o .la

build/.libs/mod_auth_browserid.so: $(SRCS) $(HDRS)
	@mkdir -p build/
	@cd build && for file in $^ ; do ln -sf ../$$file . ; done
	@cd build && $(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $(subst src/,,$(SRCS))

all:  build/.libs/mod_auth_browserid.so

install: build/mod_auth_browserid.la
	$(APXS_PATH) -i $<

clean:
	-rm -rf build
