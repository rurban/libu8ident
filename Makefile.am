ACLOCAL_AMFLAGS = -I m4 --install ${ACLOCAL_FLAGS}
PERL = @PERL@
WGET = @WGET@
RONN = @RONN@
PANDOC = @PANDOC@
GPERF = @GPERF@
WARN_CFLAGS = @WARN_CFLAGS@
CROARING_PATH = @CROARING_PATH@
AM_CFLAGS = -I$(srcdir)/include -I$(builddir) -I$(srcdir) $(WARN_CFLAGS)
lib_LTLIBRARIES = libu8ident.la
include_HEADERS = include/u8ident.h
c_sources = $(srcdir)/u8ident.c $(srcdir)/u8idnorm.c $(srcdir)/u8idscr.c $(srcdir)/u8idroar.c
libu8ident_la_SOURCES = u8ident.c u8idnorm.c u8idscr.c
if HAVE_CONFUS
c_sources += $(srcdir)/htable.c
libu8ident_la_SOURCES += htable.c
endif
if HAVE_CROARING
AM_CFLAGS += -I$(CROARING_PATH)
libu8ident_la_SOURCES += u8idroar.c
endif
libu8ident_la_LDFLAGS = \
	-version-info $(LIBU8IDENT_SO_VERSION) \
	-no-undefined \
	$(LDFLAGS) $(AM_LDFLAGS)
bin_PROGRAMS = u8idlint
u8idlint_SOURCES = u8idlint.c $(libu8ident_la_SOURCES)
u8idlint_CFLAGS = $(AM_CFLAGS) $(U8IDLINT_CFLAGS)
u8idlint_LDADD = $(u8idlint_LIBS)
EXTRA_HEADERS = c11-safe.h unitr39.h

pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = libu8ident.pc
dist_man1_MANS = u8idlint.1
dist_man3_MANS = u8ident.3
docdir = $(datadir)/libu8ident
PCXX = P2528R0
NC   = n2932
DCURCXX = D2528R1
NCURC   = nXXXX
PDF = doc/$(PCXX).pdf doc/$(DCURCXX).pdf doc/$(NC).pdf doc/$(NCURC).pdf
doc_DATA = README.md NEWS NOTICE LICENSE \
	   doc/c11.md doc/$(PCXX).md doc/$(DCURCXX).md doc/$(NC).md \
	   doc/$(NCURC).md doc/$(NCURC).patch \
	   doc/tr31-bugs.md 
if HAVE_PANDOC
doc_DATA += $(PDF)
html_DATA = doc/$(DCURCXX).html doc/$(NCURC).html
doc_DATA += $(html_DATA)
endif
HDRS =  u8id_gc.h scripts.h confus.h u8id_private.h u8idscr.h u8idroar.h \
	un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h \
	confus_croar.h mark.h medial.h unic11.h unitr39.h scripts16.h gconfus.h htable.h
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
	texts/arabic-1.c          texts/math-1.c         texts/math-2.c         texts/math-2.cc \
	texts/bidi-sec-1.c        texts/bidi-sec-2.c     texts/bidi-sec-3.c     texts/bidi-sec-4.cc \
	texts/homo-1.c            texts/homo-sec-1.c     texts/homo-sec-2.c \
	texts/nfc-1.c             texts/nfkc-1.c \
	texts/bidi-sec-1.tst      texts/bidi-sec-1-c11.tst  texts/bidi-sec-1-allowed.tst \
	texts/bidi-sec-2.tst      texts/bidi-sec-2-c11.tst  texts/bidi-sec-2-allowed.tst \
	texts/bidi-sec-2-allowed.tst \
	texts/homo-sec-1.tst   	  texts/homo-sec-1-p1.tst   texts/homo-1.tst \
	texts/bidi-sec-1.py	  texts/homo-sec-1.js	 texts/homo-sec-1.py    texts/norm-sec-1.py \
	texts/norm-sec-1.cperl	  texts/norm-sec-1.raku

EXTRA_DIST = mkscripts.pl mkconfus.pl mktest-norm.pl mkmark.pl mkgc.pl mkmedial.pl makefile.gnu \
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
$(srcdir)/confus.h: $(srcdir)/mkconfus.pl # confusables.txt
	-cd $(srcdir) && $(PERL) mkconfus.pl -c
$(srcdir)/gconfus.h.in: $(srcdir)/mkconfus.pl # confusables.txt
	-cd $(srcdir) && $(PERL) mkconfus.pl -c
$(srcdir)/mark.h: $(srcdir)/mkmark.pl # UnicodeData.txt
	cd $(srcdir) && $(PERL) mkmark.pl
$(srcdir)/medial.h: $(srcdir)/mkmedial.pl # UnicodeData.txt
	cd $(srcdir) && $(PERL) mkmedial.pl
$(srcdir)/su8id_gc.h: $(srcdir)/mkgc.pl # UnicodeData.txt
	cd $(srcdir) && $(PERL) mkgc.pl
$(srcdir)/gconfus.h: $(srcdir)/gconfus.h.in
	-if test -n "$(GPERF)"; then cd $(srcdir) && $(GPERF) -n gconfus.h.in > gconfus.h.tmp && sed -e's,static const unsigned int asso_values,(void)len; static const unsigned int asso_values,' <gconfus.h.tmp >gconfus.h && rm gconfus.h.tmp; fi

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
	  LC_ALL=C help2man -N -s1 -p $(PACKAGE_NAME) --manual "U8IDENT Manual $(VERSION)" -o $$p ./$$base$(EXEEXT); done

# Create the normalization headers via a current perl
Unicode-Normalize: un8ifcan.h
	if test -d $(srcdir)/Unicode-Normalize; then \
	  cd $(srcdir)/Unicode-Normalize && git pull --rebase && cd ..; \
	else \
	  git clone https://github.com/rurban/Unicode-Normalize; fi
regen-norm: Unicode-Normalize un8ifcan.h
	cd $(srcdir)/Unicode-Normalize && \
	  $(PERL) mkheader && \
	  $(PERL) Makefile.PL && \
	  make && \
	  $(PERL) mkheader -ind -std && \
	  cd - && cp Unicode-Normalize/un8if*.h .
# Download some UCD files and create scripts.h
regen-scripts:
	-$(WGET) -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
	-$(WGET) -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
	-$(WGET) -N https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt
	-$(WGET) -N https://www.unicode.org/Public/UNIDATA/DerivedCoreProperties.txt
	-$(WGET) -N https://www.unicode.org/Public/UNIDATA/DerivedNormalizationProps.txt
	-$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierType.txt
	-$(WGET) -N https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
	$(PERL) mkscripts.pl
	$(PERL) mkgc.pl
	$(PERL) mkmark.pl
	-$(MAKE) unitr39.h
# Download some UCD files and create confus.h
regen-confus:
	-$(WGET) -N https://www.unicode.org/Public/security/latest/confusables.txt
	-$(PERL) mkconfus.pl
docs: $(doc_DATA) $(PDF)
	-test -d doc || mkdir doc
pdf: $(PDF)

if HAVE_PANDOC
doc/$(PCXX).html:
	-test -d doc || mkdir doc
	cp $(srcdir)/doc/$(PCXX).html $@
doc/$(PCXX).pdf:
	-test -d doc || mkdir doc
	cp $(srcdir)/doc/$(PCXX).pdf $@
doc/$(NC).html:
	-test -d doc || mkdir doc
	cp $(srcdir)/doc/$(NC).html $@
doc/$(NC).pdf:
	-test -d doc || mkdir doc
	cp $(srcdir)/doc/$(NC).pdf $@

doc/$(DCURCXX).html: $(srcdir)/doc/$(DCURCXX).md
	-test -d doc || mkdir doc
	$(PANDOC) -s -o $@ $(srcdir)/doc/$(DCURCXX).md --metadata title="$(DCURCXX) - C++ Identifier Security using Unicode Standard Annex 39"
	-cp $@ $(srcdir)/$@
doc/$(DCURCXX).pdf: $(srcdir)/doc/$(DCURCXX).md
	-test -d doc || mkdir doc
	$(PANDOC) -s --pdf-engine=xelatex -o $@ $(srcdir)/doc/$(DCURCXX).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono"
	-cp $@ $(srcdir)/$@
doc/$(NCURC).html: $(srcdir)/doc/$(NCURC).md
	-test -d doc || mkdir doc
	$(PANDOC) -s -o $@ $(srcdir)/doc/$(NCURC).md --metadata title="$(NCURC) - C Identifier Security using Unicode Standard Annex 39 v3"
	-cp $@ $(srcdir)/$@
doc/$(NCURC).pdf: $(srcdir)/doc/$(NCURC).md
	-test -d doc || mkdir doc
	$(PANDOC) -s --pdf-engine=xelatex -o $@ $(srcdir)/doc/$(NC).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono" --metadata title="$(NCURC) - C Identifier Security using Unicode Standard Annex 39 v3"
	-cp $@ $(srcdir)/$@
endif

Dockerfile.pandoc: $(srcdir)/makefile.gnu
	echo "FROM fedora:36" >Dockerfile.pandoc
	echo "RUN yum -y install pandoc texlive-xetex dejavu-sans-mono-fonts dejavu-serif-fonts dejavu-sans-fonts" >> Dockerfile.pandoc
	echo "RUN useradd --no-log-init -U user -u 1000 -m" >> Dockerfile.pandoc
	echo "USER user" >> Dockerfile.pandoc
	echo "WORKDIR /home/user" >> Dockerfile.pandoc
	docker build -t pandoc -f Dockerfile.pandoc $(srcdir)
docker-html: Dockerfile.pandoc
	-docker run -u user -v $(abs_srcdir)/doc:/doc -it pandoc pandoc -s -o /doc/$(DCURCXX).html /doc/$(DCURCXX).md
	chown $$USER:$$USER $(srcdir)/doc/$(DCURCXX).html
docker-pdf: Dockerfile.pandoc
	-docker run -u user -v $(abs_srcdir)/doc:/doc -it pandoc pandoc -s --pdf-engine=xelatex -o /doc/$(DCURCXX).pdf /doc/$(DCURCXX).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono"
	chown $$USER:$$USER $(srcdir)/doc/$(DCURCXX).pdf

patch-c-doc: doc/$(NCURC).patch
	cd $(srcdir) && patch -f doc/$(NCURC).md doc/$(NCURC).patch
regen-c-patch: doc/$(DCURCXX).md doc/$(NCURC).md
	-cd $(srcdir) && diff -bu doc/$(DCURCXX).md doc/$(NCURC).md >doc/$(NCURC).patch

regen-all: regen-scripts regen-norm regen-confus regen-man $(doc_DATA) doc/$(DCURCXX).html doc/$(DCURCXX).html

.PHONY: regen-all regen-scripts regen-norm regen-confus check-asan check-norm scan-build man \
	pkg docs patch-c-doc regen-c-patch docker-html docker-pdf

EXTRA_PROGRAMS = mktr39 test test-texts example
TESTS = test example
if !HAVE_WINDOWS
EXTRA_PROGRAMS += test_asan
TESTS += test-texts.test u8idlint.test
endif
test_SOURCES = test.c $(libu8ident_la_SOURCES)
test_CFLAGS = $(AM_CFLAGS)
test_texts_SOURCES = test-texts.c $(libu8ident_la_SOURCES)
test_texts_CFLAGS = $(AM_CFLAGS) $(U8IDLINT_CFLAGS)
test_texts_LDADD = $(u8idlint_LIBS)
mktr39_SOURCES = mktr39.c $(libu8ident_la_SOURCES)
mktr39_CFLAGS = $(AM_CFLAGS)
example_SOURCES = example.c
example_LDADD = libu8ident.la
test_asan_CFLAGS = $(AM_CFLAGS) -g -fsanitize=address
test_asan_SOURCES = test.c $(libu8ident_la_SOURCES)

if HAVE_CROARING
# test_LDADD = u8idroar.lo
# TODO perf also requires mkconfus.pl without -c
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
mkroar: mkroar.c
	@echo "ERROR mkroar requires roaring.c (--with-croaring)"
endif

c11-all.h unitr39.h: mktr39$(EXEEXT) scripts.h mark.h medial.h
	./mktr39$(EXEXT)
if !HAVE_WINDOWS
	-[ "$(srcdir)" != "." ] && mv -f c11-all.h unitr39.h $(srcdir)/
else
	-copy /y c11-all.h unitr39.h $(srcdir)/
endif

if !HAVE_WINDOWS
check-all: check check-asan check-norms check-profiles check-tr31
check-extra: check-all check-mdl check-all-combinations
	shellcheck *.test test-all-fast.sh  test-all.sh
else
check-all: check check-norms check-profiles check-tr31
check-extra: check-all check-mdl check-all-combinations
endif

check-asan: test_asan
	if ./test_asan$(EXEEXT); then rm test_asan$(EXEEXT); else exit; fi

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
	      $(c_sources) -o test-norm$(EXEEXT) && \
	  ./test-norm$(EXEEXT) norm || exit; \
	done; \
	rm test-norm$(EXEEXT)
check-profiles: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in 2 3 4 5 6 C11_6 TR39_4; do \
	    echo PROFILE_$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_PROFILE=$$n -Wfatal-errors $(srcdir)/test.c \
	      $(c_sources) -o test-profiles$(EXEEXT) && \
	    ./test-profiles$(EXEEXT) profile || exit; \
	done
	for n in TR39 C11STD; do \
	    echo PROFILE_$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_PROFILE_$${n} -Wfatal-errors $(srcdir)/test.c \
	      $(c_sources) -o test-profiles$(EXEEXT) && \
	    ./test-profiles$(EXEEXT) profile || exit; \
	done; \
	rm test-profiles$(EXEEXT)
check-tr31: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in ALLOWED TR39 ID XID C11 C23 ALLUTF8 NONE; do \
	    echo U8ID_TR31=$${n}; \
	    $(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) -DU8ID_TR31=$${n} -Wfatal-errors $(srcdir)/test.c \
	      $(c_sources) -o test-tr31$(EXEEXT) && \
	    ./test-tr31$(EXEEXT) xid || exit; \
	done; \
	rm test-tr31$(EXEEXT)
check-all-combinations: $(libu8ident_la_SOURCES) $(include_HEADERS) $(HDRS)
	for n in NFKC NFC NFKD NFD FCD FCC; do \
	  for p in 2 3 4 5 6 C11_6 TR39_4; do \
	    for x in ALLOWED TR39 ID XID C11 C23 ALLUTF8 NONE; do \
	      if [ $$n != NFC ] && [ $$p = TR39_4 -o $$x = TR39 -o $$x = C23 ]; then \
		echo "skip -DU8ID_NORM=$$n -DU8ID_PROFILE=$$p -DU8ID_TR31=$$x"; \
              else \
	        echo "check -DU8ID_NORM=$$n -DU8ID_PROFILE=$$p -DU8ID_TR31=$$x"; \
	        $(COMPILE) -DU8ID_PROFILE=$$p -DU8ID_NORM=$$n -DU8ID_TR31=$$x \
		  -Wfatal-errors $(srcdir)/test.c \
		  $(c_sources) -o test-profiles$(EXEEXT) && \
	        ./test-profiles$(EXEEXT) || exit; \
	      fi; \
	    done; \
	  done; \
	done; \
	rm ./test-profiles$(EXEEXT)
# gem install mdl
check-mdl check-docs:
	cd $(srcdir) && mdl *.md doc/*.md

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

dist-hook:
	echo dist-hook distdir="$(distdir)"
	echo $(VERSION) > $(distdir)/.version

CLEANFILES = test$(EXEEXT) test-texts$(EXEEXT) test-asan$(EXEEXT) test-profiles$(EXEEXT) \
	     test-tr31$(EXEEXT) test-prof{2,3,4,5,6,TR39_4,C11_6,TR39,C11STD}$(EXEEXT) \
	     test-norm-{NFKC,NFC,FCC,NFKD,NFD,FCD}$(EXEEXT) mkroar$(EXEEXT) perf$(EXEEXT) \
	     texts.tst mktr39$(EXEEXT) example$(EXEEXT)
DISTCLEANFILES = config.log u8ident.3 u8idlint.1 $(html_DATA) homo-sec-1.tst.rst \
	     test-texts.test doc/$(NCURC).pdf
distclean-compile:
	-rm -f *.tab.c
	-rm -rf .deps
	-[ "$(srcdir)" != "." ] && rm -rf $(builddir)/texts
MAINTAINERCLEANFILES  = *~ Makefile.in Makefile
LIBTOOL_DISTCLEAN_FILES = \
	aclocal.m4 \
	configure \
	config.h.in \
	build-aux/compile \
	build-aux/config.guess \
	build-aux/config.sub \
	build-aux/depcomp \
	build-aux/install-sh \
	build-aux/ltmain.sh \
	build-aux/missing \
	m4/libtool.m4 \
	m4/ltoptions.m4 \
	m4/ltsugar.m4 \
	m4/ltversion.m4 \
	m4/lt~obsolete.m4
