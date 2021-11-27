CC := cc
CFLAGS := -Wall -Wextra -O2
AR := ar
RANLIB := ranlib
# This should to be a recent perl, matching the target unicode version
PERL := perl

HEADER = include/u8ident.h
HDRS = u8id_private.h hangul.h un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h scripts.h
SRC = u8ident.c u8idscr.c u8idnorm.c

scripts.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt
	$(PERL) mkscripts.pl

libu8ident.a: $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -c u8ident.c -o u8ident.o
	$(CC) $(CFLAGS) -Iinclude -c u8idscr.c -o u8idscr.o
	$(CC) $(CFLAGS) -Iinclude -c u8idnorm.c -o u8idnorm.o
	$(AR) $(ARFLAGS) $@ u8ident.o u8idscr.o u8idnorm.o
	$(RANLIB) $@

.PHONY: check clean regen-scripts regen-norm
check: libu8ident.a test.c
	$(CC) $(CFLAGS) -I. -Iinclude test.c -L. -lu8ident -o test
	./test

clean:
	rm u8ident.o u8idnorm.o u8idscr.o libu8ident.a test

# Create the normalization headers via a current perl
regen-norm:
	git clone https://github.com/rurban/Unicode-Normalize
	cd Unicode-Normalize && \
	  $(PERL) Makefile.PL && \
	  make && \
	  $(PERL) mkheader -ind -std && \
	  cp un8if*.h ../ && cd ..
# Download UCD and create scripts.h
regen-scripts:
	wget -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
	wget -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
	$(PERL) mkscripts.pl
