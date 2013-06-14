ifeq ($(APXS_PATH),)
APXS_PATH=/usr/sbin/apxs
endif

MY_LDFLAGS=-lcurl -lyajl
# Note that gcc flags are passed through apxs, so preface with -Wc
MY_CFLAGS=-Wc,-I. -Wc,-Wall -Wc,-g
SRCS=src/mod_authn_persona.c src/cookie.c src/verify.c
HDRS=src/cookie.h src/defines.h src/config.h src/verify.h

.SUFFIXES: .c .o .la

build/.libs/mod_authn_persona.so: $(SRCS) $(HDRS)
	@mkdir -p build/
	@cd build && for file in $^ ; do ln -sf ../$$file . ; done
	@cd build && $(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $(subst src/,,$(SRCS))

all:  build/.libs/mod_authn_persona.so

install: build/mod_authn_persona.la
	$(APXS_PATH) -i $<

clean:
	-rm -rf build
