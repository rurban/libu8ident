# -*- Makefile -*-
#DEFINES = -DU8ID_NORM=NFKC -DU8ID_PROFILE=4 -DDISABLE_CHECK_XID
DEFINES :=
CC := cc
CFLAGS := -Wall -Wextra -O2
AR := ar
RANLIB := ranlib
# dnf install rubygem-ronn-ng
RONN := ronn
# Maintainer only
# This should to be a recent perl, matching the target unicode version
PERL := perl
WGET := wget

VERSION = 0.0
HEADER = include/u8ident.h
NORMHDRS = un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
HDRS = u8id_private.h scripts.h $(NORMHDRS) hangul.h
SRC = u8ident.c u8idscr.c u8idnorm.c
LIB = libu8ident.a
DOCS = README.md NOTICE
MAN = u8ident.3
PREFIX = usr
PKG = libu8ident-$(VERSION)
PKG_BIN = $(PKG)-`uname -m`

all: $(LIB) $(MAN)

$(LIB): $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c u8ident.c -o u8ident.o
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c u8idscr.c -o u8idscr.o
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c u8idnorm.c -o u8idnorm.o
	$(AR) $(ARFLAGS) $@ u8ident.o u8idscr.o u8idnorm.o
	$(RANLIB) $@

scripts.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt
	$(PERL) mkscripts.pl

.PHONY: check check-asan clean regen-scripts regen-norm install man dist
check: libu8ident.a test.c
	$(CC) $(CFLAGS) $(DEFINES) -g -I. -Iinclude test.c -L. -lu8ident -o test
	./test

check-asan: test.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) $(DEFINES) -g -fsanitize=address -I. -Iinclude test.c u8ident.c u8idscr.c u8idnorm.c -o test-asan
	./test-asan

clean:
	-rm -f u8ident.o u8idnorm.o u8idscr.o libu8ident.a test test-asan

# Maintainer-only
# Check coverage and sizes for all --with-norm configure combinations
check-norms: $(SRC) $(HEADER) $(HDRS)
	for n in NFC NFD NFKC NFKD FCC FCD; do \
            echo $$n; \
            cc -DU8ID_NORM=$$n -O3 -Wall -Wno-return-local-addr -Wfatal-errors -Iinclude -c u8idnorm.c -o u8idnorm.o && \
            ls -gGh u8idnorm.o; \
        done

# Create the normalization headers via a current perl
Unicode-Normalize: un8ifcan.h
	if test -d Unicode-Normalize; then \
	  cd Unicode-Normalize && git pull --rebase && cd ..; \
	else \
	  git clone https://github.com/rurban/Unicode-Normalize; fi
regen-norm: Unicode-Normalize un8ifcan.h
	cd Unicode-Normalize && \
	  $(PERL) Makefile.PL && \
	  make && \
	  $(PERL) mkheader -ind -std && \
	  cd - && cp Unicode-Normalize/un8if*.h .
# Download some UCD files and create scripts.h
regen-scripts:
	$(WGET) -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
	$(WGET) -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
	$(WGET) -N https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierType.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	$(PERL) mkscripts.pl

# End Maintainer-only

man: $(MAN)

RONN_ARGS=--roff --manual "U8IDENT Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.3: README.md
	$(RONN) $(RONN_ARGS) < README.md > $@

dist-bin: $(LIB) $(MAN)
	-rm -rf $(PKG)
	-mkdir -p $(PKG)/$(PREFIX)/include
	-mkdir -p $(PKG)/$(PREFIX)/lib
	-mkdir -p $(PKG)/$(PREFIX)/share/doc/libu8ident
	-mkdir -p $(PKG)/$(PREFIX)/share/man/man3
	install -m0644 $(HEADER) $(PKG)/$(PREFIX)/include
	install -m0644 $(LIB) $(PKG)/$(PREFIX)/lib
	install -m0644 $(MAN) $(PKG)/$(PREFIX)/share/man/man3
	install -m0644 $(DOCS) $(PKG)/$(PREFIX)/share/doc/libu8ident
	tar cfz $(PKG_BIN).tar.gz -C $(PKG) .
	-rm -rf $(PKG)

dist-src:
	-rm -rf $(PKG)
	-mkdir -p $(PKG)/include
	cp $(HEADER) $(PKG)/include/
	cp `git ls-tree -r --name-only HEAD` $(PKG)/
	tar cfz $(PKG).tar.gz $(PKG)
	rm -rf $(PKG)

install: $(LIB) $(MAN)
	-mkdir -p $(DESTDIR)/$(PREFIX)/include
	-mkdir -p $(DESTDIR)/$(PREFIX)/lib
	-mkdir -p $(DESTDIR)/$(PREFIX)/share/doc/libu8ident
	-mkdir -p $(DESTDIR)/$(PREFIX)/share/man/man3
	install -m0644 $(HEADER) $(DESTDIR)/$(PREFIX)/include
	install -m0644 $(LIB) $(DESTDIR)/$(PREFIX)/lib
	install -m0644 $(MAN) $(DESTDIR)/$(PREFIX)/share/man/man3
	install -m0644 $(DOCS) $(DESTDIR)/$(PREFIX)/share/doc/libu8ident