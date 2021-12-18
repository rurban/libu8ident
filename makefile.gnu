# -*- Makefile -*-
#DEFINES = -DU8ID_NORM=NFKC -DU8ID_PROFILE=4 -DDISABLE_CHECK_XID
HAVE_CONFUS := 1
DEFINES :=
CC := cc
CFLAGS := -Wall -Wextra -O2
AR := ar
RANLIB := ranlib
# dnf install rubygem-ronn-ng
RONN := ronn
# Maintainer only
VERSION = 0.0
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
ifneq (,$(wildcard roaring.c))
DEFINES += -DHAVE_CROARING
HDRS += confus_croar.h roaring.h
endif
#OBJS = u8ident.o u8idscr.o u8idnorm.o u8idroar.o
OBJS = $(SRC:.c=.o)
LIB = libu8ident.a
DOCS = README.md NOTICE LICENSE
MAN = u8ident.3
PREFIX = usr
PKG = libu8ident-$(VERSION)
PKG_BIN = $(PKG)-`uname -m`

ifeq (x86_64,$(shell uname -m))
CFLAGS += -march=native
endif

all: $(LIB) $(MAN)

.c.o:
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c $< -o $@
u8idnorm.o: u8idnorm.c u8id_private.h hangul.h $(NORMHDRS) $(HEADER)
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c u8idnorm.c -o $@
u8idroar.o: u8idroar.c u8id_private.h $(HEADER) confus_croar.h
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -c u8idroar.c -o $@

$(LIB): $(SRC) $(HEADER) $(HDRS) $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

scripts.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt
	$(PERL) mkscripts.pl
confus.h: mkconfus.pl mkroar.c # confusables.txt
	$(PERL) mkconfus.pl
confus_croar.h allow_croar.h nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h: mkroar.c mkconfus.pl
	$(PERL) mkconfus.pl

.PHONY: check check-asan check-norms check-profiles check-xid \
	clean regen-scripts regen-norm regen-confus install man dist-src dist-bin clang-format
check: test
	./test
test: test.c $(LIB)
	$(CC) $(CFLAGS) $(DEFINES) -g -I. -Iinclude test.c -L. -lu8ident -o test
check-all: check check-norms check-profiles check-xid check-asan

check-asan: test.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) $(DEFINES) -g -fsanitize=address -I. -Iinclude test.c $(SRC) -o test-asan
	./test-asan

perf: perf.c u8idroar.c $(HEADER) $(HDRS) confus_croar.h \
      nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h allow_croar.h
	$(CC) $(CFLAGS) $(DEFINES) -DPERF_TEST -I. -Iinclude perf.c u8idroar.c -o perf && \
	./perf

clean:
	-rm -f u8ident.o u8idnorm.o u8idscr.o u8idroar.o libu8ident.a \
	       perf mkroar allowed_croar.bin confus_croar.bin \
	       test test-asan test-xid-{EN,DIS}ABLE test-prof{2,3,4,5,6} test-norm-{NFKC,NFC,FCC,NFKD,NFD,FCD}

# Maintainer-only
# Check coverage and sizes for all configure combinations
check-norms: $(SRC) $(HEADER) $(HDRS)
	for n in NFKC NFC FCC NFKD NFD FCD; do \
            echo $$n; \
            cc -DU8ID_NORM=$$n -O3 -Wall -Wno-return-local-addr -Wfatal-errors -Iinclude -c u8idnorm.c -o u8idnorm.o && \
            ls -gGh u8idnorm.o; \
	    $(CC) $(CFLAGS) $(DEFINES) -DU8ID_NORM=$$n -Wno-return-local-addr -I. -Iinclude test.c $(SRC) \
	      -o test-norm-$$n && ./test-norm-$$n norm; \
        done
check-profiles: $(SRC) $(HEADER) $(HDRS)
	for n in 2 3 4 5 6; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS) $(DEFINES) -DU8ID_PROFILE=$$n -Wno-return-local-addr -I. -Iinclude test.c $(SRC) \
	      -o test-prof$$n && ./test-prof$$n profile; \
        done
check-xid: $(SRC) $(HEADER) $(HDRS)
	for n in DISABLE ENABLE; do \
            echo $${n}_CHECK_XID; \
	    $(CC) $(CFLAGS) $(DEFINES) -D$${n}_CHECK_XID -Wno-return-local-addr -I. -Iinclude test.c $(SRC) \
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
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierType.txt
	$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
	$(PERL) mkscripts.pl
regen-confus:
	$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	$(PERL) mkconfus.pl

clang-format:
	clang-format -i *.c include/*.h scripts.h confus.h u8id*.h

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
