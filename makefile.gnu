# -*- Makefile -*-
CC := cc
CFLAGS := -Wall -Wextra -O2
AR := ar
RANLIB := ranlib
# This should to be a recent perl, matching the target unicode version
PERL := perl
WGET := wget

HEADER = include/u8ident.h
NORMHDRS = un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
HDRS = u8id_private.h scripts.h $(NORMHDRS) hangul.h
SRC = u8ident.c u8idscr.c u8idnorm.c

libu8ident.a: $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -c u8ident.c -o u8ident.o
	$(CC) $(CFLAGS) -Iinclude -c u8idscr.c -o u8idscr.o
	$(CC) $(CFLAGS) -Iinclude -c u8idnorm.c -o u8idnorm.o
	$(AR) $(ARFLAGS) $@ u8ident.o u8idscr.o u8idnorm.o
	$(RANLIB) $@

scripts.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt
	$(PERL) mkscripts.pl

.PHONY: check check-asan clean regen-scripts regen-norm
check: libu8ident.a test.c
	$(CC) $(CFLAGS) -g -I. -Iinclude test.c -L. -lu8ident -o test
	./test

check-asan: test.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) -g -fsanitize=address -I. -Iinclude test.c u8ident.c u8idscr.c u8idnorm.c -o test-asan
	./test-asan

# Check coverage and sizes for all --with-norm configure combinations
check-norms: $(SRC) $(HEADER) $(HDRS)
	for n in NFC NFD NFKC NFKD FCC FCD; do \
            echo $$n; \
            cc -DU8ID_NORM=$$n -O3 -Wall -Wno-return-local-addr -Wfatal-errors -Iinclude -c u8idnorm.c -o u8idnorm.o && \
            ls -gGh u8idnorm.o; \
        done

clean:
	-rm -f u8ident.o u8idnorm.o u8idscr.o libu8ident.a test test-asan

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
	$(WGET) -N http://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt
	$(PERL) mkscripts.pl
