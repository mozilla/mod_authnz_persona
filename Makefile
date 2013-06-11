ifeq ($(APXS_PATH),)
APXS_PATH=/usr/sbin/apxs
endif

MY_LDFLAGS=-lcurl -lyajl
# Note that gcc flags are passed through apxs, so preface with -Wc
MY_CFLAGS=-Wc,-I. -Wc,-Wall
SRCS=mod_auth_browserid.c

.SUFFIXES: .c .o .la

build/.libs/mod_auth_browserid.so: $(SRCS)
	@mkdir -p build/
	@cd build && for file in $^ ; do ln -sf ../$$file . ; done
	@cd build && $(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $^

all:  build/.libs/mod_auth_browserid.so

install: build/.libs/mod_auth_browserid.so
	$(APXS_PATH) -i build/mod_auth_browserid.c

clean:
	-rm -rf build
