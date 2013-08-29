AUTOMAKE_OPTIONS=foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

module_LTLIBRARIES = mod_authn_persona.la
bin_PROGRAMS = bin2c

moduledir = $(shell $(APXS) -q LIBEXECDIR)

EXTRA_DIST=t README.md build/mod_authn_persona.spec build/test.pl .indent.pro src/signin.html

APR_CONFIG = $(shell $(APXS) -q APR_CONFIG)
APU_CONFIG = $(shell $(APXS) -q APU_CONFIG)
APR_CFLAGS = $(shell $(APR_CONFIG) --cflags --cppflags --includes) -Wall -Werror -Wno-unused-function
APU_CFLAGS = $(shell $(APU_CONFIG) --includes)
HTTPD_CFLAGS = $(shell $(APXS) -q CFLAGS) -I $(shell $(APXS) -q INCLUDEDIR)

AM_CFLAGS = -Isrc $(HTTPD_CFLAGS) $(APR_CFLAGS) $(APU_CFLAGS) $(YAJL_CFLAGS) $(LIBCURL_CPPFLAGS)

mod_authn_persona_la_SOURCES = src/mod_authn_persona.c src/cookie.c src/verify.c src/cookie.h src/defines.h src/verify.h
noinst_mod_authn_persona_la_SOURCES = src/signin_page.h
BUILT_SOURCES = src/signin_page.h
mod_authn_persona_la_LDFLAGS = -module -avoid-version $(YAJL_LIBS) $(LIBCURL)

bin2c_SOURCES = tools/bin2c.c

CLEANFILES = src/signin_page.h

src/signin_page.h: src/signin.html bin2c$(EXEEXT)
	./bin2c$(EXEEXT) src/signin.html > src/signin_page.h

check: test

test: all t/TEST
	$(PERL) t/TEST

t/TEST: build/test.pl
	$(PERL) build/test.pl -apxs $(APXS)

dist-hook:
	rm -rf `find $(distdir)/t -name .svn`

rpm: dist
	rpmbuild -ta $(DIST_ARCHIVES)

indent:
	indent -i4 -npsl -di0 -br -nce -d0 -cli0 -npcs -nfc1 -nut *.c $(SOURCES)
