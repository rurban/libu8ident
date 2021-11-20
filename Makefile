CC := cc
AR := ar
RANLIB := ranlib
PERL := perl

HEADER = include/u8ident.h
HDRS = u8id_private.h hangul.h un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
SRC = u8ident.c u8idscr.c u8idnorm.c

libu8ident.a: $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -c u8ident.c -o u8ident.o
	$(CC) $(CFLAGS) -Iinclude -c u8idscr.c -o u8idscr.o
	$(CC) $(CFLAGS) -Iinclude -c u8idnorm.c -o u8idnorm.o
	$(AR) $(ARFLAGS) $@ u8ident.o u8idscr.o u8idnorm.o
	$(RANLIB) $@

.PHONY: check clean
check: libu8ident.a test.c
	$(CC) $(CFLAGS) -Iinclude test.c -L. -lu8ident -o test
	./test

clean:
	rm u8ident.o u8idnorm.o u8idscr.o libu8ident.a test

# TODO patch U8IDENT_UNICODE_VERSION,
# Download UCD and create scripts.h
regen-norm:
	git clone https://github.com/rurban/Unicode-Normalize
	cd Unicode-Normalize && \
	  $(PERL) Makefile.PL && \
	  make && \
	  $(PERL) mkheader -ind -std && \
	  cp un8if*.h ../ && cd ..
regen-scripts:
	wget -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
	wget -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
	$(PERL) mkscripts.pl
