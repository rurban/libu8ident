# -*- Makefile -*-
#DEFS := -DU8ID_NORM=NFKC -DU8ID_PROFILE=4 -DDISABLE_CHECK_XID
DEFINES = ${DEFS} -DHAVE___BUILTIN_FFS
HAVE_CONFUS := 1
CC := cc
CFLAGS := -Wall -Wextra
AR := ar
RANLIB := ranlib
GPERF := gperf
# dnf install rubygem-ronn-ng
RONN := ronn
# Maintainer only
VERSION := $(shell build-aux/git-version-gen .version)
SO_MAJ = 1
DEFINES += -DPACKAGE_VERSION="\"$(VERSION)\""
# This should to be a recent perl, matching the target unicode version
PERL := perl
WGET := wget
PANDOC := pandoc
# End Maintainer-only

HEADER = include/u8ident.h
NORMHDRS = un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h
HDRS = u8id_private.h u8id_gc.h scripts.h $(NORMHDRS) hangul.h \
       mark.h medial.h unic11.h scripts16.h htable.h
SRC = u8ident.c u8idscr.c u8idnorm.c
ifeq (${HAVE_CONFUS}, 1)
SRC += u8idroar.c htable.c
HDRS += u8idroar.h confus.h gconfus.h
DEFINES += -DHAVE_CONFUS
endif
ifneq (,$(wildcard /usr/include/sys/stat.h))
DEFINES += -DHAVE_SYS_STAT_H
endif
ifneq (,$(wildcard /usr/include/dirent.h))
DEFINES += -DHAVE_DIRENT_H
endif
ifneq (,$(wildcard /usr/include/getopt.h))
DEFINES += -DHAVE_GETOPT_H
endif
ifneq (,$(wildcard /usr/include/uniwbrk.h))
DEFINES += -DHAVE_UNIWBRK_H -DHAVE_LIBUNISTRING
LIBUNISTR = -lunistring
else
LIBUNISTR =
endif
ifneq (,$(wildcard roaring.c))
DEFINES += -DHAVE_CROARING
HDRS += confus_croar.h roaring.h
else
ifneq (,$(wildcard ../CRoaring/roaring.c))
DEFINES += -DHAVE_CROARING
CFLAGS += -I../CRoaring
HDRS += confus_croar.h roaring.h
endif
endif
ALLHDRS = $(HDRS) unitr39.h
#OBJS = u8ident.o u8idscr.o u8idnorm.o u8idroar.o
OBJS = $(SRC:.c=.o)
LIB = libu8ident.a
SOLIB = libu8ident.so
PCXX = P2528R0
NC   = n2916
DCURCXX = D2528R1
NCURC   = n2932
DOCS = README.md NEWS NOTICE LICENSE doc/c11.md doc/$(PCXX).html doc/$(DCURCXX).html \
	doc/$(PCXX).md doc/$(DCURCXX).md doc/$(NC).html doc/$(NC).md doc/$(NCURC).patch \
	doc/$(NCURC).html doc/$(NCURC).md \
	doc/tr31-bugs.md
MAN3 = u8ident.3
MAN1 = u8idlint.1
MAN = $(MAN1) $(MAN3)
PREFIX = usr
PKG = libu8ident-$(VERSION)
PKG_BIN = $(PKG)-`uname -m`

CFLAGS_REL = $(CFLAGS) -O2 -DNDEBUG
CFLAGS_PERF = $(CFLAGS) -O2 -DNDEBUG
CFLAGS_DBG = $(CFLAGS) -g -DDEBUG
LTOFLAGS =

MACHINE := $(shell uname -m)
ifeq (x86_64,$(MACHINE))
DEFINES += -DHAVE_SYS_STAT_H
LTOFLAGS = -flto
CFLAGS_REL += -march=native
CFLAGS_PERF += -march=native
endif

RUN_LD_PATH=LD_LIBRARY_PATH=.
OS := $(shell uname -s)
ifeq (Darwin,$(OS))
RUN_LD_PATH=DYLD_LIBRARY_PATH=.
else
ifeq (AIX,$(OS))
RUN_LD_PATH=LIBPATH=.
else
ifeq (HP-UX,$(OS))
RUN_LD_PATH=SHLIB_PATH=.
endif
endif
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
CFLAGS_PERF += -Wno-return-local-addr
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

most: $(LIB) $(SOLIB) u8idlint doc/$(DCURCXX).html

all: mktr39 most test-texts test perf docs

.version: makefile.gnu
	build-aux/git-version-gen .version

.c.o:
	$(CC) $(CFLAGS_REL) $(LTOFLAGS) $(DEFINES) -Iinclude -c $< -o $@
.c.i:
	$(CC) $(CFLAGS) $(DEFINES) -Iinclude -E -c $< -o $@
u8idnorm.o: u8idnorm.c u8id_private.h hangul.h $(NORMHDRS) $(HEADER)
	$(CC) $(CFLAGS_REL) $(LTOFLAGS) $(DEFINES) -Iinclude -c u8idnorm.c -o $@
u8idroar.o: u8idroar.c u8id_private.h $(HEADER) confus_croar.h
	$(CC) $(CFLAGS_REL) $(LTOFLAGS) $(DEFINES) -Iinclude -c u8idroar.c -o $@

$(LIB): $(SRC) $(HEADER) $(ALLHDRS) $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

$(SOLIB): $(SRC) $(HEADER) $(ALLHDRS)
	$(CC) $(CFLAGS_REL) $(LTOFLAGS) -shared -fPIC $(DEFINES) -Iinclude \
	  -Wl,-soname,$(SOLIB).$(SO_MAJ) -o $@.$(SO_MAJ) $(SRC)
	-rm -f $(SOLIB)
	ln -s $(SOLIB).$(SO_MAJ) $(SOLIB)

scripts.h scripts16.h: mkscripts.pl # Scripts.txt ScriptExtensions.txt DerivedNormalizationProps.txt
	$(PERL) mkscripts.pl
gconfus.h.in: mkconfus.pl # confusables.txt
	$(PERL) mkconfus.pl -c
confus.h: mkconfus.pl mkroar.c # confusables.txt
	$(PERL) mkconfus.pl -c
gconfus.h: gconfus.h.in
	$(GPERF) -n gconfus.h.in > gconfus.h.tmp && sed -e's,static const unsigned int asso_values,(void)len; static const unsigned int asso_values,' <gconfus.h.tmp >gconfus.h && rm gconfus.h.tmp
confus_croar.h: mkroar.c mkconfus.pl
	$(PERL) mkconfus.pl -c
mark.h: mkmark.pl # UnicodeData.txt
	$(PERL) mkmark.pl
u8id_gc.h: mkgc.pl # UnicodeData.txt
	$(PERL) mkgc.pl
medial.h: mkmedial.pl # UnicodeData.txt
	$(PERL) mkmedial.pl
allowed_croar.h nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h: mkroar.c mkconfus.pl FORCE
	$(PERL) mkconfus.pl

u8idlint: u8idlint.c unitr39.h unic11.h $(LIB)
	$(CC) $(CFLAGS_REL) -fpie $(DEFINES) -I. -Iinclude u8idlint.c -o $@ $(LIB) $(LIBUNISTR)

.PHONY: check check-all check-extra check-asan check-norms check-profiles check-tr31 check-mdl \
	check-all-combinations clean regen-scripts regen-norm regen-confus regen-u8idlint-test \
	install man dist-src dist clang-format docs

ifeq (-DHAVE_CONFUS,$(DEFINES))
check: test test-texts u8idlint example
	./test
	./test-texts > texts.tst
	diff texts.tst texts/result.lst && rm texts.tst
	./u8idlint.test
	$(RUN_LD_PATH) ./example
else
ifeq (-DHAVE_CONFUS -DHAVE_CROARING,$(DEFINES))
check: test test-texts u8idlint example
	./test
	./test-texts > texts.tst
	diff texts.tst texts/result.lst && rm texts.tst
	./u8idlint.test
	$(RUN_LD_PATH) ./example
else
check: test test-texts u8idlint example
	./test
	./test-texts > texts.tst
	diff texts.tst texts/result.lst && rm texts.tst
	./u8idlint.test
	$(RUN_LD_PATH) ./example
endif
endif

check-all: check check-norms check-profiles check-tr31 check-asan
check-extra: check-all check-all-combinations check-mdl
	shellcheck *.test test-all-fast.sh  test-all.sh

test: test.c $(SRC) $(HEADER) $(ALLHDRS)
	$(CC) $(CFLAGS_DBG) $(DEFINES) -I. -Iinclude test.c $(SRC) -o test
test-texts: test-texts.c $(SRC) $(HEADER) $(ALLHDRS)
	$(CC) $(CFLAGS_DBG) -O1 $(DEFINES) -I. -Iinclude test-texts.c $(SRC) -o test-texts $(LIBUNISTR)
example: example.c $(SOLIB)
	$(CC) $(CFLAGS_DBG) $(DEFINES) -Iinclude example.c -o $@ -L. -lu8ident
regen-u8idlint-test: u8idlint
	-./u8idlint -xtr39 texts/homo-sec-1.c >texts/homo-sec-1.tst
	-./u8idlint -p1 -xc11 texts/homo-sec-1.c >texts/homo-sec-1-p1.tst
	-./u8idlint -xc11 texts/homo-1.c >texts/homo-1.tst
	-./u8idlint -xallowed texts/bidi-sec-1.c >texts/bidi-sec-1.tst
	-./u8idlint -xc11 texts/bidi-sec-1.c >texts/bidi-sec-1-c11.tst
	-./u8idlint -xtr39 texts/bidi-sec-1.c >texts/bidi-sec-1-c26.tst
	-./u8idlint -xascii texts/bidi-sec-2.c >texts/bidi-sec-2-ascii.tst
	-./u8idlint -xallowed texts/bidi-sec-2.c >texts/bidi-sec-2-allowed.tst
	-./u8idlint -xid texts/bidi-sec-2.c >texts/bidi-sec-2.tst
	-./u8idlint -xc11 texts/bidi-sec-2.c >texts/bidi-sec-2-c11.tst

c11-all.h unitr39.h: mktr39 scripts.h mark.h medial.h
	./mktr39
mktr39: mktr39.c $(SRC) $(HEADER) $(HDRS)
	$(CC) $(CFLAGS_DBG) -O1 $(DEFINES) -DU8ID_PROFILE_TR39 -I. -Iinclude mktr39.c $(SRC) -o $@
check-asan: test.c $(SRC) $(HEADER) $(ALLHDRS)
	$(CC) $(CFLAGS_DBG) $(DEFINES) -fsanitize=address -I. -Iinclude test.c $(SRC) -o test-asan
	./test-asan
# gem install mdl
check-mdl:
	mdl *.md doc/*.md

perf: perf.c u8idroar.c $(HEADER) $(ALLHDRS) \
      nfkc_croar.h nfc_croar.h nfkd_croar.h nfd_croar.h allowed_croar.h confus_croar.h mark.h scripts16.h
	$(CC) $(CFLAGS_PERF) -Wno-unused-function $(DEFINES) -DPERF_TEST -I. -Iinclude \
	  perf.c u8idroar.c -o perf && \
	./perf

clean:
	-rm -f u8ident.o u8idnorm.o u8idscr.o u8idroar.o $(LIB) $(SOLIB) \
	       perf mkroar mktr39 u8idlint example \
	       test test-texts test-asan test-tr31 \
	       test-prof{2,3,4,5,6,TR39_4,C11_6,TR39,C11STD} \
	       test-norm-{NFKC,NFC,FCC,NFKD,NFD,FCD} \

# Maintainer-only
# Check coverage and sizes for all configure combinations
check-norms: $(SRC) $(HEADER) $(ALLHDRS)
	for n in NFKC NFC FCC NFKD NFD FCD; do \
            echo $$n; \
            $(CC) $(CFLAGS_REL) -DU8ID_NORM=$$n -Wfatal-errors -Iinclude -c u8idnorm.c -o u8idnorm.o && \
	      ls -gGh u8idnorm.o; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_NORM=$$n -I. -Iinclude test.c $(SRC) \
	      -o test-norm-$$n && \
	    if ./test-norm-$$n norm; then rm test-norm-$$n; else exit; fi; \
        done
check-profiles: $(SRC) $(HEADER) $(ALLHDRS)
	for n in 2 3 4 5 6 C11_6 TR39_4; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_PROFILE=$$n -I. -Iinclude test.c $(SRC) \
	      -o test-prof$$n && \
	    if ./test-prof$$n profile; then rm test-prof$$n; else exit; fi; \
        done
	for n in TR39 C11STD; do \
            echo PROFILE_$${n}; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_PROFILE_$${n} -I. -Iinclude test.c $(SRC) \
	      -o test-prof$$n && \
	    if ./test-prof$$n profile; then rm test-prof$$n; else exit; fi; \
        done
check-tr31: $(SRC) $(HEADER) $(ALLHDRS)
	for x in ALLOWED TR39 ID XID C11 C23 ALLUTF8 NONE; do \
            echo U8ID_TR31_$$x; \
	    $(CC) $(CFLAGS_DBG) $(DEFINES) -DU8ID_TR31=$$x -I. -Iinclude test.c $(SRC) \
	      -o test-xid-$$x && \
	    if ./test-xid-$$x xid; then rm test-xid-$$x; else exit; fi; \
        done
check-all-combinations: $(SRC) $(HEADER) $(ALLHDRS)
	for n in NFKC NFC NFKD NFD FCD FCC; do \
	  for p in 2 3 4 5 6 C11_6 TR39_4; do \
	    for x in ALLOWED TR39 ID XID C11 C23 ALLUTF8 NONE; do \
	      if [ $$n != NFC ] && [ $$p = TR39_4 -o $$x = TR39 -o $$x = C23 ]; then \
		echo "skip -DU8ID_NORM=$$n -DU8ID_PROFILE=$$p -DU8ID_TR31=$$x"; \
              else \
	        echo "check -DU8ID_NORM=$$n -DU8ID_PROFILE=$$p -DU8ID_TR31=$$x"; \
	        $(CC) $(CFLAGS_DBG) $(DEFINES) -I. -Iinclude -DU8ID_PROFILE=$$p -DU8ID_NORM=$$n -DU8ID_TR31=$$x \
		  -Wfatal-errors test.c $(SRC) \
	          -o test-profiles && \
	        ./test-profiles || exit; \
	      fi; \
	    done; \
	  done; \
	done; \
	rm test-profiles

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

docs: $(DOCS)
# doc/P2528R0.* and doc/n2916.* are frozen
html: doc/$(DCURCXX).html doc/$(NCURC).html
pdf: doc/$(DCURCXX).pdf doc/$(NCURC).pdf
doc/$(DCURCXX).html: doc/$(DCURCXX).md
	-$(PANDOC) -s -o $@ doc/$(DCURCXX).md --metadata title="$(DCURCXX) - C++ Identifier Security using Unicode Standard Annex 39"
doc/$(DCURCXX).pdf: doc/$(DCURCXX).md
	-$(PANDOC) -s --pdf-engine=xelatex -o $@ doc/$(DCURCXX).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono"
doc/$(NCURC).html: doc/$(NCURC).md
	-$(PANDOC) -s -o $@ doc/$(NCURC).md --metadata title="$(NCURC) - C Identifier Security using Unicode Standard Annex 39 v2"
doc/$(NCURC).pdf: doc/$(NCURC).md
	-$(PANDOC) -s --pdf-engine=xelatex -o $@ doc/$(NCURC).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono" --metadata title="$(NCURC) - C Identifier Security using Unicode Standard Annex 39 v2"

Dockerfile.pandoc: makefile.gnu
	echo "FROM fedora:35" >Dockerfile.pandoc
	echo "RUN yum -y install pandoc texlive-xetex dejavu-sans-mono-fonts dejavu-serif-fonts dejavu-sans-fonts" >> Dockerfile.pandoc
	echo "RUN useradd --no-log-init -U user -u 1000 -m" >> Dockerfile.pandoc
	echo "USER user" >> Dockerfile.pandoc
	echo "WORKDIR /home/user" >> Dockerfile.pandoc
	docker build -t pandoc -f Dockerfile.pandoc .
docker-html: Dockerfile.pandoc
	-docker run -u user -v `pwd`/doc:/doc -it pandoc pandoc -s -o /doc/$(DCURCXX).html /doc/$(DCURCXX).md
	chown $$USER:$$USER doc/$(DCURCXX).html
docker-pdf: Dockerfile.pandoc
	-docker run -u user -v `pwd`/doc:/doc -it pandoc pandoc -s --pdf-engine=xelatex -o /doc/$(DCURCXX).pdf /doc/$(DCURCXX).md --variable mainfont="DejaVu Serif" --variable sansfont="DejaVu Sans" --variable monofont="DejaVu Sans Mono"
	chown $$USER:$$USER doc/$(DCURCXX).pdf

patch-c-doc:
	patch -f doc/$(NCURC).md doc/$(NCURC).patch
regen-c-patch:
	-diff -bu doc/$(DCURCXX).md doc/$(NCURC).md >doc/$(NCURC).patch

clang-format:
	clang-format -i *.c include/*.h scripts.h confus.h mark.h scripts16.h u8id*.h
GTAGS: $(SRC) $(HEADER) $(ALLHDRS)
	ls $(SRC) $(HEADER) $(ALLHDRS) | gtags -f -

# End Maintainer-only

man: $(MAN)

RONN_ARGS=--roff --manual "U8IDENT Manual $(VERSION)" --organization=rurban/libu8ident
u8ident.3: README.md
	$(RONN) $(RONN_ARGS) < README.md > $@
u8idlint.1: u8idlint
	LC_ALL=C help2man -N -s1 -p libu8ident --manual "U8IDENT Manual $(VERSION)" -o $@ ./u8idlint$(EXEEXT)

dist: $(LIB) $(MAN) $(DOCS)
	-rm -rf $(PKG)
	$(MAKE) -f makefile.gnu install DESTDIR="$(PKG)"
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
	install -m0644 $(MAN3) $(DESTDIR)/$(PREFIX)/share/man/man3
	install -m0644 $(DOCS) $(DESTDIR)/$(PREFIX)/share/doc/libu8ident
