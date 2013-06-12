ifeq ($(APXS_PATH),)
APXS_PATH=/usr/sbin/apxs
endif

MY_LDFLAGS=-lcurl -lyajl
# Note that gcc flags are passed through apxs, so preface with -Wc
MY_CFLAGS=-Wc,-I. -Wc,-Wall
SRCS=mod_auth_browserid.c cookie.c
HDRS=cookie.h defines.h config.h

.SUFFIXES: .c .o .la

build/.libs/mod_auth_browserid.so: $(SRCS) $(HDRS)
	@mkdir -p build/
	@cd build && for file in $^ ; do ln -sf ../$$file . ; done
	@cd build && $(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $^

all:  build/.libs/mod_auth_browserid.so

install: build/mod_auth_browserid.la
	$(APXS_PATH) -i $<

clean:
	-rm -rf build
