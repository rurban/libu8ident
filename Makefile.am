ACLOCAL_AMFLAGS = -I m4 --install ${ACLOCAL_FLAGS}
PERL = @PERL@
WGET = @WGET@
WARN_CFLAGS = @WARN_CFLAGS@
CROARING_PATH = @CROARING_PATH@
AM_CFLAGS = -I$(srcdir)/include -I$(srcdir) -I$(builddir) $(WARN_CFLAGS)
lib_LTLIBRARIES = libu8ident.la
include_HEADERS = include/u8ident.h
libu8ident_la_SOURCES = u8ident.c u8idnorm.c u8idscr.c
if HAVE_CROARING
libu8ident_la_CFLAGS = $(CFLAGS) $(AM_CFLAGS) -I$(CROARING_PATH)
libu8ident_la_SOURCES += u8idroar.c
endif
libu8ident_la_LDFLAGS = \
	-version-info $(LIBU8IDENT_SO_VERSION) \
	-no-undefined \
	$(LDFLAGS) $(AM_LDFLAGS)
pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = libu8ident.pc
man_MANS = u8ident.3
docdir = $(datadir)/libu8ident
doc_DATA = README.md NOTICE LICENSE
HDRS =  scripts.h confus.h u8id_private.h u8idscr.h u8idroar.h \
	un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h \
	confus_croar.h
EXTRA_DIST = mkscripts.pl mkconfus.pl mktest-norm.pl makefile.gnu $(HDRS) $(doc_DATA)

.c.i:
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -E -o $@ $<

.c.ii:  # no linemarkers
	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -E -P -o $@ $<

$(srcdir)/scripts.h: $(srcdir)/mkscripts.pl
	cd $(srcdir) && $(PERL) mkscripts.pl
$(srcdir)/confus.h: $(srcdir)/mkconfus.pl
	cd $(srcdir) && $(PERL) mkconfus.pl
# emacs flymake-mode
check-syntax:
	test -n "$(CHK_SOURCES)" && \
	  $(COMPILE) -o /dev/null -S $(CHK_SOURCES)
.PHONY: check-syntax clang-format

clang-format:
	clang-format -i $(srcdir)/*.c $(srcdir)/include/*.h $(srcdir)/scripts.h $(srcdir)/confus.h $(srcdir)/u8id*.h

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
# Download some UCD files and create confus.h
regen-confus:
	$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	$(PERL) mkconfus.pl
regen-all: regen-scripts regen-norm regen-confus

.PHONY: regen-all regen-scripts regen-norm regen-confus check-asan check-norm scan-build man

EXTRA_PROGRAMS = test
test_SOURCES = test.c
test_LDADD = $(lib_LTLIBRARIES)
if HAVE_CROARING
test_LDADD += u8idroar.lo
EXTRA_PROGRAMS += perf
perf_CFLAGS = $(CFLAGS) $(AM_CFLAGS) -I$(CROARING_PATH)
perf_SOURCES = perf.c
perf_LDADD = u8idroar.lo
endif
TESTS = test

check-all: check check-asan check-norms check-profiles check-xid

check-asan: test.c $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	$(CC) $(CFLAGS) $(AM_CFLAGS) -g -fsanitize=address \
	  $(srcdir)/test.c $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c \
	  -o test-asan$(EXEEXT)
	./test-asan$(EXEEXT)

# Check coverage and sizes for all --with-norm configure combinations
# e.g. amd64-gcc:   NFKC 217K, NFC+FCC 182K, NFD 113K, NFD 78K, FCD 52K
# e.g. amd64-clang: NFKC 218K, NFC+FCC 183K, NFD 114K, NFD 78K, FCD 52K
# clang has no -Wno-return-local-addr
check-norms:
	for n in NFKC NFC FCC NFKD NFD FCD; do \
            echo $$n; \
            $(CC) $(CFLAGS) $(AM_CFLAGS) -DU8ID_NORM=$$n -Os -Wfatal-errors -c $(srcdir)/u8idnorm.c -o u8idnorm.o && \
            ls -gGh u8idnorm.o; \
        done
check-profiles: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in 2 3 4 5 6; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS) $(AM_CFLAGS) -DU8ID_PROFILE=$$n -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-profiles && \
	    ./test-profiles profile; \
        done
check-xid: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in DISABLE ENABLE; do \
            echo $${n}_CHECK_XID; \
	    $(CC) $(CFLAGS) $(AM_CFLAGS) -D$${n}_CHECK_XID -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-xid && \
	    ./test-xid xid; \
        done

# clang-analyzer.llvm.org, debian: clang-tools-{6.0,7}, redhat: clang-analyzer
SCAN_BUILD = scan-build
scan-build: clean
	$(SCAN_BUILD) -V -o $(srcdir)/.analysis $(MAKE) -j4 &

man: $(man_MANS)

RONN_ARGS=--roff --manual "u8ident Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.3: README.md
	$(RONN) $(RONN_ARGS) < $< > $@

CLEANFILES = test$(EXEEXT) test-asan$(EXEEXT) test-profiles$(EXEEXT) test-xid$(EXEEXT)
DISTCLEANFILES = config.log
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
	missing \
	m4/libtool.m4 \
	m4/ltoptions.m4 \
	m4/ltsugar.m4 \
	m4/ltversion.m4 \
	m4/lt~obsolete.m4

