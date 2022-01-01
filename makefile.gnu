# -*- Makefile -*-
DEFINES := -DHAVE___BUILTIN_FFS
#DEFINES := -DU8ID_NORM=NFKC -DU8ID_PROFILE=4 -DDISABLE_CHECK_XID
HAVE_CONFUS := 1
CC := cc
CFLAGS := -Wall -Wextra
AR := ar
RANLIB := ranlib
# dnf install rubygem-ronn-ng
RONN := ronn
# Maintainer only
VERSION = 0.1
DEFINES += -DPACKAGE_VERSION="\"$(VERSION)\""
# This should to be a recent perl, matching the target unicode version
PERL := perl
WGET := wget
# End Maintainer-only

HEADER = include/u8ident.h
NORMHDRS = un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
HDRS = u8id_private.h scripts.h $(NORMHDRS) hangul.h
SRC = u8ident.c u8idscr.c u8idnorm.c
ifeq (${HAVE_CONFUS}, 1)
SRC += u8idroar.c
HDRS += u8idroar.h confus.h
DEFINES += -DHAVE_CONFUS
endif
ifneq (,$(wildcard /usr/include/sys/stat.h))
DEFINES += -DHAVE_SYS_STAT_H
endif
ifneq (,$(wildcard /usr/include/dirent.h))
DEFINES += -DHAVE_DIRENT_H
endif
ifneq (,$(wildcard roaring.c))
DEFINES += -DHAVE_CROARING
HDRS += confus_croar.h roaring.h
endif
#OBJS = u8ident.o u8idscr.o u8idnorm.o u8idroar.o
OBJS = $(SRC:.c=.o)
LIB = libu8ident.a
DOCS = README.md NOTICE LICENSE
MAN3 = u8ident.3
MAN1 = u8idlint.1
MAN = $(MAN1) $(MAN3)
PREFIX = usr
PKG = libu8ident-$(VERSION)
PKG_BIN = $(PKG)-`uname -m`

CFLAGS_REL = $(CFLAGS) -O3 -DNDEBUG
CFLAGS_DBG = $(CFLAGS) -g -DDEBUG

MACHINE := $(shell uname -m)
ifeq (x86_64,$(MACHINE))
CFLAGS_REL += -march=native -flto
endif
# cc prints name as cc, not gcc. so check for the copyright banner
CC_COPY := $(shell $(CC) --version | head -n2 | tail -n1 | cut -c1-7)
# gcc has "Copyright (C) 2020 Free Software Foundation, Inc"
# clang would have "Target: ..."
# icc would have "Copyright (c) (C) 1985-2014 Intel Corporation"
# pcc has "Portable C Compiler 1.2.0.DEVEL 20200630 for x86_64-pc-linux-gnu" on the 1st line
# chibicc has no --version, just --help
ifeq (Copyrig,$(CC_COPY))
IS_GCC = 1
CFLAGS_REL += -Werror -Wno-return-local-addr
CFLAGS_DBG += -Wno-return-local-addr
else
ifeq (Target:,$(CC_COPY))
IS_CLANG = 1
CFLAGS_REL += -Werror
else
ifeq (Portable C Compiler,$(shell $(CC) --version | cut -c1-19))
IS_PCC = 1
CFLAGS_REL += -Werror
endif
endif
endif

all: $(LIB) $(MAN) u8idlint

.c.o:
	$(CC) $(CFLAGS_REL) $(DEFINES) -Iinclude -c $< -o $@
u8idnorm.o: u8idnorm.c u8id_private.h hangul.h $(NORMHDRS) $(HEADER)
	$(CC) $(CFLAGS_REL) $(DEFINES) -Iinclude -c u8idnorm.c -o $@
u8idroar.o: u8idroar.c u8id_private.h $(HEADER) confus_croar.h
	$(CC) $(CFLAGS_REL) $(DEFINES) -Iinclude -c u8idroar.c -o $@

$(LIB): $(SRC) $(HEADER) $(HDRS) $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

scripts.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt DerivedNormalizationProps.txt
	$(PERL) mkscripts.pl
confus.h: mkconfus.pl mkroar.c # confusables.txt
	$(PERL) mkconfus.pl -c
confus_croar.h: mkroar.c mkconfus.pl
	$(PERL) mkconfus.pl -c
mark.h: mkmark.pl # UnicodeData.txt
	$(PERL) mkmark.pl
allowed_croar.h nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h: mkroar.c mkconfus.pl
	$(PERL) mkconfus.pl

u8idlint: u8idlint.c $(LIB)
	$(CC) $(CFLAGS_REL) $(DEFINES) -I. -Iinclude u8idlint.c -o $@ $(LIB)

.PHONY: check check-asan check-norms check-profiles check-xid \
	clean regen-scripts regen-norm regen-confus install man dist-src dist-bin clang-format

ifeq (-DHAVE_CONFUS,$(DEFINES))
check: test test-texts test-c11
	./test
	./test-texts > texts.tst
	diff texts.tst texts/result.lst && rm texts.tst
	./test-c11
	./u8idlint.test
else
ifeq (-DHAVE_CONFUS -DHAVE_CROARING,$(DEFINES))
check: test test-texts test-c11
	./test
	./test-texts > texts.tst
	diff texts.tst texts/result.lst && rm texts.tst
	./test-c11
	./u8idlint.test
else
check: test test-c11
	./test
	./test-c11
	./u8idlint.test
endif
endif

check-all: check check-norms check-profiles check-xid check-asan

test: test.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS_DBG) $(DEFINES) -I. -Iinclude test.c $(SRC) -o test
test-texts: test-texts.c $(SRC) $(HEADER) $(HDRS) mark.h
	$(CC) $(CFLAGS_DBG) -O1 $(DEFINES) -I. -Iinclude test-texts.c $(SRC) -o test-texts
test-c11: test-c11.c $(SRC) $(HEADER) $(HDRS) mark.h
	$(CC) $(CFLAGS_DBG) -O1 $(DEFINES) -DU8ID_PROFILE_SAFEC23 -I. -Iinclude test-c11.c $(SRC) -o test-c11
check-asan: test.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS_DBG) $(DEFINES) -fsanitize=address -I. -Iinclude test.c $(SRC) -o test-asan
	./test-asan

perf: perf.c u8idroar.c $(HEADER) $(HDRS) \
      nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h allowed_croar.h confus_croar.h mark.h
	$(CC) $(CFLAGS_REL) -Wno-unused-function $(DEFINES) -DPERF_TEST -I. -Iinclude \
	  perf.c u8idroar.c -o perf && \
	./perf

clean:
	-rm -f u8ident.o u8idnorm.o u8idscr.o u8idroar.o libu8ident.a \
	       perf mkroar \
	       test test-texts test-asan test-xid-{EN,DIS}ABLE \
	       test-prof{2,3,4,5,6,C23_4,C11_6,SAFEC23,C11STD} \
	       test-norm-{NFKC,NFC,FCC,NFKD,NFD,FCD}

# Maintainer-only
# Check coverage and sizes for all configure combinations
check-norms: $(SRC) $(HEADER) $(HDRS)
	for n in NFKC NFC FCC NFKD NFD FCD; do \
            echo $$n; \
            $(CC) $(CFLAGS_REL) -DU8ID_NORM=$$n -Wfatal-errors -Iinclude -c u8idnorm.c -o u8idnorm.o && \
	      ls -gGh u8idnorm.o; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_NORM=$$n -I. -Iinclude test.c $(SRC) \
	      -o test-norm-$$n && ./test-norm-$$n norm; \
        done
check-profiles: $(SRC) $(HEADER) $(HDRS)
	for n in 2 3 4 5 6 C11_6 C23_4; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_PROFILE=$$n -I. -Iinclude test.c $(SRC) \
	      -o test-prof$$n && ./test-prof$$n profile; \
        done
	for n in SAFEC23 C11STD; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_PROFILE_$${n} -I. -Iinclude test.c $(SRC) \
	      -o test-prof$$n && ./test-prof$$n profile; \
        done
check-xid: $(SRC) $(HEADER) $(HDRS)
	for n in DISABLE ENABLE; do \
            echo $${n}_CHECK_XID; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -D$${n}_CHECK_XID -I. -Iinclude test.c $(SRC) \
	      -o test-xid-$$n && ./test-xid-$$n xid; \
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
	$(WGET) -N https://www.unicode.org/Public/UNIDATA/DerivedCoreProperties.txt
	$(WGET) -N https://www.unicode.org/Public/UNIDATA/DerivedNormalizationProps.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierType.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
	$(PERL) mkscripts.pl
regen-confus:
	$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	$(PERL) mkconfus.pl

clang-format:
	clang-format -i *.c include/*.h scripts.h confus.h u8id*.h
GTAGS: $(SRC) $(HEADER) $(HDRS)
	ls $(SRC) $(HEADER) $(HDRS) | gtags -f -

# End Maintainer-only

man: $(MAN)

RONN_ARGS=--roff --manual "U8IDENT Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.3: README.md
	$(RONN) $(RONN_ARGS) < README.md > $@
u8idlint.1: u8idlint
	help2man -N -s1 -p libu8ident --manual "U8IDENT Manual $(VERSION)" -o $@ ./u8idlint$(EXEEXT)

dist-bin: $(LIB) $(MAN)
	-rm -rf $(PKG)
	-mkdir -p $(PKG)/$(PREFIX)/include
	-mkdir -p $(PKG)/$(PREFIX)/lib
	-mkdir -p $(PKG)/$(PREFIX)/bin
	-mkdir -p $(PKG)/$(PREFIX)/share/doc/libu8ident
	-mkdir -p $(PKG)/$(PREFIX)/share/man/man3
	install -m0644 $(HEADER) $(PKG)/$(PREFIX)/include
	install -m0755 u8idlint $(PKG)/$(PREFIX)/bin
	install -m0644 $(LIB) $(PKG)/$(PREFIX)/lib
	install -m0644 $(MAN1) $(PKG)/$(PREFIX)/share/man/man1
	install -m0644 $(MAN3) $(PKG)/$(PREFIX)/share/man/man3
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
	-mkdir -p $(DESTDIR)/$(PREFIX)/bin
	-mkdir -p $(DESTDIR)/$(PREFIX)/share/doc/libu8ident
	-mkdir -p $(DESTDIR)/$(PREFIX)/share/man/man3
	install -m0644 $(HEADER) $(DESTDIR)/$(PREFIX)/include
	install -m0644 $(LIB) $(DESTDIR)/$(PREFIX)/lib
	install -m0755 u8idlint $(DESTDIR)/$(PREFIX)/bin
	install -m0644 $(MAN1) $(DESTDIR)/$(PREFIX)/share/man/man1
	install -m0644 $(MAN2) $(DESTDIR)/$(PREFIX)/share/man/man3
	install -m0644 $(DOCS) $(DESTDIR)/$(PREFIX)/share/doc/libu8ident
