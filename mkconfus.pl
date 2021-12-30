#!/usr/bin/env perl -s
# libu8ident - Check unicode security guidelines for identifiers.
# Copyright 2014, 2021 Reini Urban
# SPDX-License-Identifier: Apache-2.0
#
# Create confus.h from https://www.unicode.org/Public/security/latest/confusables.txt
# with mkconfus.pl -c.
# perf needs mkconfus.pl without -c to generate all headers.
#
# Note that this is just a binary-search in an unoptimized,
# uncompressed array, without any values.  It might be smaller and
# faster with gperf or cbitset/croaring.

use vars qw($c);
use strict;
use Config;
my $confus = "confusables.txt";
for ($confus) {
  if (!-e $_) {
    system("wget -N https://www.unicode.org/Public/security/latest/$_");
  }
}

my (@CONF, @ucd_version, $started);
open my $CONF, "<", $confus or die "$confus $!";
while (<$CONF>) {
  if (!$started) {
    if (/^# Version: (\d+)\.(\d)\.(\d)/) { @ucd_version = ($1,$2,$3); }
    if (/^# For documentation and/) { $started++; }
    next unless $started;
  } else {
    if (/^([0-9A-F]{4,5}) ;\s+([0-9A-F]{4,5}) ;/) {
      my ($from, $to1) = (hex($1), hex($2));
      push @CONF, [$from, $to1];
    }
    elsif (/^([0-9A-F]{4,5}) ;\s+([0-9A-F]{4,5}\s+){1,4} ;/) {
      my ($from, $ids) = (hex($1), $2);
      my @ids = map{ hex $_ } split(' ',$ids);
      push @CONF, [$from, @ids];
    }
  }
}
close $CONF;
@CONF = sort {$a->[0] <=> $b->[0]} @CONF;

my $ofile1 = "confus.h";
chmod 0644, $ofile1 if -e $ofile1;
open my $H1, ">", $ofile1 or die "writing $ofile1 $!";
print $H1 <<"EOF";
/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   generated by mkconfus.pl, do not modify.
   UNICODE version $ucd_version[0].$ucd_version[1]
*/
#include <stdint.h>

/* Sorted set of all confusables,
   from https://www.unicode.org/Public/security/latest/confusables.txt
 */
#ifndef EXT_SCRIPTS
const uint32_t confusables[] = {
    // clang-format off
EOF

my $ofile = "gconfus.h.in";
chmod 0644, $ofile if -e $ofile;
open my $H, ">", $ofile or die "writing $ofile $!";
print $H <<"EOF";
%{/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   generated by mkconfus.pl, do not modify.
   UNICODE version $ucd_version[0].$ucd_version[1]
*/

#include <string.h>
#include "u8id_private.h"

// v3.1 changed len type from unsigned int to size_t (gperf d519d1a821511eaa22eae6d9019a548aea21e6)
#ifdef GPERF_VERSION
#  if GPERF_VERSION < 301
#    define SIZE_TYPE unsigned int
#  else
#    define SIZE_TYPE size_t
#  endif
#else
#  define SIZE_TYPE size_t
#endif

%}
%7bit
%language=ANSI-C
%struct-type
%readonly-tables
%pic

struct _confus_gperf {uint32_t key; uint32_t *values};

%%
EOF
my $i = 0;
for my $c (@CONF) {
  printf $H1 "    0x%04X,\n", $c->[0];
  if (@$c == 2) {
    printf $H "0x%05X,\t{0x%05X,0}\n", $c->[0], $c->[1];
  } else {
    printf $H "0x%05X,\t{", $c->[0];
    pop @$c;
    for (@$c) {
      printf $H "0x%05X,", $_;
    }
    printf $H "0}\n";
  }
  $i++;
}

print $H <<'EOF';
%%

/*
 * Local variables:
 *   c-file-style: "gnu"
 * End:
 * vim: expandtab shiftwidth=4 cinoptions='\:2=2' :
 */
EOF
close $H;

print $H1 <<"EOF";
    // clang-format on
};
#else
extern const uint32_t confusables[$i];
#endif
EOF
close $H1;

print "Create serialized roaring bitmaps:\n";
my $arg = $c ? "confus" : "";
if ($^O =~ /Win32/) {
  system($Config{cc}." mkroar.c -I. -o mkroar.exe");
  if ($c) {
    system("mkroar.exe", $arg);
  } else {
    system("mkroar.exe");
  }
  # ignore vms for now
} else {
  system($Config{cc}." mkroar.c -I. -o mkroar");
  if ($c) {
    system("./mkroar", $arg);
  } else {
    system("./mkroar");
  }
}
print "\n";
# allowed not optimized. stayed with 816 array
# confus optimized from 8552 byte to 4731 byte (3 run-length encoded containers)
# NFD_N, NFC_N, NFC_M, NFKD_N, NFKC_N, NFKC_M
my @list = $c ? qw(confus)
              : qw(allowed confus nfd_n nfc_n nfc_m nfkd_n nfkc_n nfkc_m);
for my $name (@list) {
  my $c = $name . "_croar";
  my $b = $c;
  if ($name =~ /(nfk?[cd])_./) {
    $b = $1 . "_croar";
  }
  if ($name =~ /^nfk?c_m/) {
    system("xxd -i $c.bin >> $b.h");
    unlink "$c.bin";
  } else {
    open my $F, '>', "$b.h";
    print $F "/* generated via mkroar.c */\n";
    close $F;
    system("xxd -i $c.bin >> $b.h");
    unlink "$c.bin";
    print "Created $b.h\n";
  }
}
