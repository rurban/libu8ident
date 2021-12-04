ACLOCAL_AMFLAGS = -I m4 --install ${ACLOCAL_FLAGS}
PERL = @PERL@
WGET = @WGET@
EXTRA_DIST = mkscripts.pl mktest-norm.pl \
	hangul.h scripts.h u8id_private.h u8idscr.h un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
WARN_CFLAGS = @WARN_CFLAGS@
AM_CFLAGS = -I$(srcdir)/include -I$(srcdir) -I$(builddir) $(WARN_CFLAGS)
lib_LTLIBRARIES = libu8ident.la
include_HEADERS = include/u8ident.h
libu8ident_la_SOURCES = u8ident.c u8idnorm.c u8idscr.c
libu8ident_la_LDFLAGS = \
	-version-info $(LIBU8IDENT_SO_VERSION) \
	-no-undefined \
	$(LDFLAGS) $(AM_LDFLAGS)
pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = libu8ident.pc
man_DIST = u8ident.3
doc_DIST = README.md NOTICE

.c.i:
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -E -o $@ $<

.c.ii:  # no linemarkers
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -E -P -o $@ $<

scripts.h: mkscripts.pl
	$(PERL) mkscripts.pl
# emacs flymake-mode
check-syntax:
	test -n "$(CHK_SOURCES)" && \
	  $(COMPILE) -o /dev/null -S $(CHK_SOURCES)
.PHONY: check-syntax

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
	$(PERL) mkscripts.pl

.PHONY: regen-scripts regen-norm check-asan check-norm scan-build man

EXTRA_PROGRAMS = test
test_SOURCES = test.c
test_LDADD = $(lib_LTLIBRARIES)
TESTS = test

check-asan: test.c $(libu8ident_la_SOURCES)
	$(CC) $(CFLAGS) $(AM_CFLAGS) -g -fsanitize=address test.c $(libu8ident_la_SOURCES) \
	  -o test-asan$(EXEEXT)
	./test-asan$(EXEEXT)

# Check coverage and sizes for all --with-norm configure combinations
# e.g. amd64-gcc:   NFKC 217K, NFC+FCC 182K, NFD 113K, NFD 78K, FCD 52K
# e.g. amd64-clang: NFKC 218K, NFC+FCC 183K, NFD 114K, NFD 78K, FCD 52K
# clang has no -Wno-return-local-addr
check-norms:
	for n in NFKC NFC FCC NFKD NFD FCD; do \
            echo $$n; \
            $(CC) $(CFLAGS) $(AM_CFLAGS) -DU8ID_NORM=$$n -Os -Wfatal-errors -c u8idnorm.c -o u8idnorm.o && \
            ls -gGh u8idnorm.o; \
        done

# clang-analyzer.llvm.org, debian: clang-tools-{6.0,7}, redhat: clang-analyzer
SCAN_BUILD = scan-build
scan-build: clean
	$(SCAN_BUILD) -V -o $(srcdir)/.analysis $(MAKE) -j4 &

MANPAGES = u8ident.h.3
man: $(MANPAGES)

RONN_ARGS=--roff --manual "u8ident Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.h.3 : README.md
	$(RONN) $(RONN_ARGS) < $< > $@

DISTCLEANFILES  = test$(EXEEXT)
MAINTAINERCLEANFILES  = *~ Makefile.in Makefile
LIBTOOL_DISTCLEAN_FILES = \
	aclocal.m4 \
	compile \
	config.guess \
	config.h.in \
	config.sub \
	configure \
	depcomp \
	install-sh \
	ltmain.sh \
	missing
