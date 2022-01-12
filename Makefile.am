ACLOCAL_AMFLAGS = -I m4 --install ${ACLOCAL_FLAGS}
PERL = @PERL@
WGET = @WGET@
RONN = @RONN@
WARN_CFLAGS = @WARN_CFLAGS@
CROARING_PATH = @CROARING_PATH@
AM_CFLAGS = -I$(srcdir)/include -I$(builddir) -I$(srcdir) $(WARN_CFLAGS)
lib_LTLIBRARIES = libu8ident.la
include_HEADERS = include/u8ident.h
libu8ident_la_SOURCES = u8ident.c u8idnorm.c u8idscr.c
if HAVE_CROARING
AM_CFLAGS += -I$(CROARING_PATH)
libu8ident_la_SOURCES += u8idroar.c
endif
libu8ident_la_LDFLAGS = \
	-version-info $(LIBU8IDENT_SO_VERSION) \
	-no-undefined \
	$(LDFLAGS) $(AM_LDFLAGS)
bin_PROGRAMS = u8idlint
u8idlint_SOURCES = u8idlint.c u8ident.c u8idnorm.c u8idscr.c u8idroar.c
u8idlint_CFLAGS = $(AM_CFLAGS)

pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = libu8ident.pc
dist_man1_MANS = u8idlint.1
dist_man3_MANS = u8ident.3
docdir = $(datadir)/libu8ident
doc_DATA = README.md NOTICE LICENSE c11.md c23++proposal.md c23++proposal.html
HDRS =  u8id_gc.h scripts.h confus.h u8id_private.h u8idscr.h u8idroar.h \
	un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h \
	confus_croar.h mark.h unic11.h unic23.h scripts16.h
TEXTS = texts/amharic-1.txt       texts/farsi-1.txt      texts/kannada-1.txt    texts/punjabi-1.txt \
	texts/arabic-1.txt        texts/georgian-1.txt   texts/khmer-1.txt      texts/scots-gaelic-1.txt \
	texts/armenian-1.txt      texts/greek-1.txt      texts/korean-1.txt     texts/sinhala-1.txt \
	texts/bengali-1.txt       texts/gujarati-1.txt   texts/korean-2.txt     texts/swedish-1.txt \
	texts/bopomofo-1.txt      texts/hebrew-1.txt     texts/lao-1.txt        texts/tamil-1.txt \
	texts/bulgarian-1.txt     texts/hindi-1.txt      texts/latin-1.txt      texts/telugu-1.txt \
	texts/chinese-s-1.txt     texts/hungarian-1.txt  texts/malayalam-1.txt  texts/thai-1.txt \
	texts/chinese-trad-1.txt  texts/igbo-1.txt       texts/marathi-1.txt    texts/turkish-1.txt \
	texts/cyrillic-1.txt      texts/japanese-1.txt   texts/myanmar-1.txt    texts/urdu-1.txt \
	texts/english-1.txt       texts/japanese-2.txt   texts/odia-1.txt       texts/vietnamese-1.txt \
	texts/arabic-1.c          texts/math-1.c         texts/bidi-sec-1.c     texts/bidi-sec-2.c \
	texts/bidi-sec-3.c        texts/homo-1.c         texts/homo-sec-1.c     texts/nfc-1.c \
	texts/nfkc-1.c 		  texts/bidi-sec-1.tst   texts/bidi-sec-2.tst   texts/bidi-sec-1-c11.tst \
	texts/bidi-sec-2-c11.tst  texts/bidi-sec-2-allowed.tst                  texts/homo-sec-1.tst \
	texts/homo-sec-1-p1.tst   texts/homo-1.tst
EXTRA_DIST = mkscripts.pl mkconfus.pl mktest-norm.pl mkmark.pl mkgc.pl makefile.gnu \
	$(HDRS) $(doc_DATA) \
	$(TEXTS) texts/result.lst u8idlint.test mkroar.c m4/ax_gcc_builtin.m4

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
$(srcdir)/mark.h: $(srcdir)/mkmark.pl # UnicodeData.txt
	cd $(srcdir) && $(PERL) mkmark.pl
$(srcdir)/u8id_gc.h: $(srcdir)/mkgc.pl # UnicodeData.txt
	cd $(srcdir) && $(PERL) mkgc.pl
# emacs flymake-mode
check-syntax:
	test -n "$(CHK_SOURCES)" && \
	  $(COMPILE) -o /dev/null -S $(CHK_SOURCES)
.PHONY: check-syntax clang-format

clang-format:
	clang-format -i $(srcdir)/*.c $(srcdir)/include/*.h $(srcdir)/scripts.h $(srcdir)/confus.h $(srcdir)/u8id*.h

$(dist_man1_MANS) regen-man: $(bin_PROGRAMS)
	-for p in $(dist_man1_MANS); do \
	  base=`basename $$p .1`; \
	  help2man -N -s1 -p $(PACKAGE_NAME) --manual "U8IDENT Manual $(VERSION)" -o $$p ./$$base$(EXEEXT); done

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
	$(PERL) mkgc.pl
	$(PERL) mkmark.pl
	-$(MAKE) unic23.h
# Download some UCD files and create confus.h
regen-confus:
	$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	$(PERL) mkconfus.pl
c23++proposal.html: $(srcdir)/c23++proposal.md
	-markdown $(srcdir)/c23++proposal.md >$@
regen-all: regen-scripts regen-norm regen-confus regen-man c23++proposal.html

.PHONY: regen-all regen-scripts regen-norm regen-confus check-asan check-norm scan-build man pkg

EXTRA_PROGRAMS = test
TESTS = test
if !HAVE_WINDOWS
EXTRA_PROGRAMS += test-texts mkc23
TESTS += test-texts.test u8idlint.test
endif
test_SOURCES = test.c u8ident.c u8idnorm.c u8idscr.c u8idroar.c
test_CFLAGS = $(AM_CFLAGS)
test_texts_SOURCES = test-texts.c u8ident.c u8idnorm.c u8idscr.c u8idroar.c
test_texts_CFLAGS = $(AM_CFLAGS) $(TEST_TEXTS_CFLAGS)
test_texts_LDADD = $(test_texts_LIBS)
mkc23_SOURCES = mkc23.c u8ident.c u8idnorm.c u8idscr.c u8idroar.c
mkc23_CFLAGS = $(AM_CFLAGS) $(TEST_TEXTS_CFLAGS) -DU8ID_PROFILE_SAFEC23
mkc23_LDADD = $(test_texts_LIBS)

if HAVE_CROARING
test_LDADD = u8idroar.lo
EXTRA_PROGRAMS += perf
perf_CFLAGS = $(AM_CFLAGS) -DPERF_TEST
perf_SOURCES = perf.c u8idroar.c
perf_LDADD = u8idroar.lo
endif
TESTS_ENVIRONMENT = U8IDTEST_TEXTS='@top_srcdir@/texts'

test-texts.test: test-texts$(EXEEXT)

if !HAVE_CROARING
perf: perf.c
	@echo "ERROR perf requires roaring.c (--with-croaring)"
endif

if !HAVE_WINDOWS
c11-all.h unic23.h: mkc23$(EXEEXT) scripts.h mark.h
	./mkc23$(EXEXT)
	-mv -f c11-all.h unic23.h $(srcdir)/
endif

if !HAVE_WINDOWS
check-all: check check-asan check-norms check-profiles check-tr31
check-extra: check-all check-mdl check-all-combinations
	shellcheck *.test *.sh
else
check-all: check check-norms check-profiles check-tr31
check-extra: check-all check-mdl check-all-combinations
endif

check-asan: test.c $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -g -fsanitize=address \
	  $(srcdir)/test.c $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c \
	  -o test-asan$(EXEEXT)
	if ./test-asan$(EXEEXT); then rm test-asan$(EXEEXT); else exit; fi

# Check coverage and sizes for all --with-norm configure combinations
# e.g. amd64-gcc:   NFKC 217K, NFC+FCC 182K, NFD 113K, NFD 78K, FCD 52K
# e.g. amd64-clang: NFKC 218K, NFC+FCC 183K, NFD 114K, NFD 78K, FCD 52K
# clang has no -Wno-return-local-addr
check-norms:
	for n in NFKC NFC FCC NFKD NFD FCD; do \
	  echo $$n; \
	  $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_NORM=$$n -Os -Wfatal-errors \
		-c $(srcdir)/u8idnorm.c -o u8idnorm.o && \
	  ls -gGh u8idnorm.o; \
	  $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_NORM=$$n -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-norm$(EXEEXT) && \
	  ./test-norm$(EXEEXT) norm || exit; \
	done; \
	rm test-norm$(EXEEXT)
check-profiles: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in 2 3 4 5 6 C11_6 C23_4; do \
	    echo PROFILE_$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_PROFILE=$$n -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-profiles$(EXEEXT) && \
	    ./test-profiles$(EXEEXT) profile || exit; \
	done
	for n in SAFEC23 C11STD; do \
	    echo PROFILE_$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_PROFILE_$${n} -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-profiles$(EXEEXT) && \
	    ./test-profiles$(EXEEXT) profile || exit; \
	done; \
	rm test-profiles$(EXEEXT)
check-tr31: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in ALLOWED SAFEC23 ID XID C11 ALLUTF8 NONE; do \
	    echo U8ID_TR31=$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_TR31=$${n} -Wfatal-errors $(srcdir)/test.c \
	      $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c -o test-tr31$(EXEEXT) && \
	    ./test-tr31$(EXEEXT) xid || exit; \
	done; \
	rm test-tr31$(EXEEXT)
check-all-combinations: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in NFKC NFC NFKD NFD FCD FCC; do \
	  for p in 2 3 4 5 6 C11_6 C23_4; do \
	    for x in ALLOWED SAFEC23 ID XID C11 ALLUTF8 NONE; do \
	      echo "check -DU8ID_NORM=$$n -DU8ID_PROFILE=$$p -DU8ID_TR31=$$x"; \
	      $(COMPILE) -DU8ID_PROFILE=$$p -DU8ID_NORM=$$n -DU8ID_TR31=$$x \
		-Wfatal-errors $(srcdir)/test.c \
		$(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c \
		$(srcdir)/u8idroar.c -o test-profiles$(EXEEXT) && \
	      ./test-profiles$(EXEEXT) || exit; \
	    done; \
	  done; \
	done; \
	rm ./test-profiles$(EXEEXT)
# gem install mdl
check-mdl:
	cd $(srcdir) && mdl *.md

# clang-analyzer.llvm.org, debian: clang-tools-{6.0,7}, redhat: clang-analyzer
SCAN_BUILD = scan-build
scan-build: clean
	$(SCAN_BUILD) -V -o $(srcdir)/.analysis $(MAKE) -j4 &

man: $(dist_man1_MANS) $(dist_man3_MANS)

RONN_ARGS=--roff --manual "u8ident Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.3: README.md
	$(RONN) $(RONN_ARGS) < $< > $@

pkg:
	-rm -rf inst
	$(MAKE) install DESTDIR="`pwd`/inst" prefix=/$(PACKAGE_TARNAME)
if HAVE_WINDOWS
	(cd inst && zip ../$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)-$(host_triplet).zip -r $(PACKAGE_TARNAME) && cd -)
else
	tar cfz $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)-$(host_triplet).tar.gz -C inst $(PACKAGE_TARNAME)
endif
	rm -rf inst

CLEANFILES = test$(EXEEXT) test-texts$(EXEEXT) test-asan$(EXEEXT) test-profiles$(EXEEXT) \
	     test-tr31$(EXEEXT) test-prof{2,3,4,5,6,C23_4,C11_6,SAFEC23,C11STD}$(EXEEXT) \
	     test-norm-{NFKC,NFC,FCC,NFKD,NFD,FCD}$(EXEEXT) mkroar$(EXEEXT) per$(EXEEXT) \
	     texts.tst mkc23$(EXEEXT)
DISTCLEANFILES = config.log u8ident.3 u8idlint.1 c23++proposal.html $(srcdir)/c11-all.sh
dist-clean-local:
	-[ $(builddir) != $(srcdir) ] && rm -rf $(builddir)/texts
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
	m4/lt~obsolete.m4 \
	test-texts.test
