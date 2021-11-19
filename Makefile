CC := cc
AR := ar
RANLIB := ranlib
HEADER = include/u8ident.h
HDRS = hangul.h  un8ifcan.h  un8ifcmb.h  un8ifcmp.h  un8ifexc.h

libu8ident.a: u8idnorm.c u8idscr.c $(HEADER) $(HDRS)
	$(CC) $(CFLAGS) -Iinclude -c u8idnorm.c -o u8idnorm.o
	$(CC) $(CFLAGS) -Iinclude -c u8idscr.c -o u8idscr.o
	$(AR) $(ARFLAGS) $@ u8idnorm.o u8idscr.o
	$(RANLIB) $@

.PHONY: check clean
check: libu8ident.a test.c
	$(CC) $(CFLAGS) -Iinclude test.c -L. -lu8ident -o test
	./test

clean:
	rm u8idnorm.o u8idscr.o libu8ident.a test
