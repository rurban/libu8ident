#!/usr/bin/env perl
# libu8ident - Check unicode security guidelines for identifiers.
# Copyright 2014, 2021 Reini Urban
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Create mark.h Combining_Mark (Mc | Me | Mn)

use strict;
use Config;
my $ucd = "UnicodeData.txt";
if (!-e $ucd) {
  system("wget -N https://www.unicode.org/Public/UNIDATA/$ucd");
}

my $mark_h = "mark.h";
my (@MARK, @NSM, @NSM_CP, %NSM);
open my $UCD, "<", $ucd or die "$ucd $!";
my ($from, $to, $oldto);
while (<$UCD>) {
  my @l = split ';';
  my $mark = $l[2];
  if ($mark =~ /^M[cen]$/) {
    $to = hex($l[0]);
    if (!$from) {
      push @MARK, [$to, $to];
      $from = $to;
    } else {
      $oldto = $MARK[$#MARK]->[1];
      if ($oldto + 1 != $to) {
        push @MARK, [$to, $to];
        $from = $to;
      } else { # update last
        $MARK[$#MARK]->[1] = $to;
      }
    }
    my $name = $l[1];
    my $n = $l[10];
    if ($name =~ /^COMBINING / && $l[4] eq 'NSM' && $n =~ /^NON-SPACING /) {
      $n =~ s/^NON-SPACING //;
      my $nsm = $n;
      push @NSM, $nsm;
      push @NSM_CP, $to;
    }
  }
}
$NSM{'DOT ABOVE'} = [ chr('i') ];
seek($UCD,0,0);
while (<$UCD>) {
  my @l = split ';';
  my $name = $l[1];
  # FIXME: HIRAGANA LETTER PA;Lo;0;L;306F 309A
  if ($name =~ /LETTER .+ WITH .+/) {
    for my $nsm (@NSM) {
      if ($name =~ /LETTER .+ WITH \Q$nsm\E$/) {
        my $cp = hex $l[0];
        if (exists $NSM{$nsm}) {
          push @{$NSM{$nsm}}, $cp;
        } else {
          $NSM{$nsm} = [ $cp ];
        }
      }
    }
  }
}
close $UCD;

if (!-w $mark_h) {
  chmod 0644, $mark_h;
}
open my $H, ">", $mark_h or die "writing $mark_h $!";
print $H <<'EOF';
/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   All Combining_Mark (Mc | Me | Mn),
   All letters with non-spacing combining marks.
   Generated by mkmark.pl, do not modify.
*/
#include <stdint.h>

EOF

printf $H <<'EOF', scalar @MARK;
/* All Combining Marks, sorted */
#ifdef EXTERN_SCRIPTS
extern const struct range_bool mark_list[%u];
#else
const struct range_bool mark_list[] = {
    // clang-format off
EOF
for my $r (@MARK) {
  printf $H "    { 0x%X, 0x%X },\n", $r->[0], $r->[1];
}
printf $H <<'EOF';
    // clang-format on
};
#endif
EOF

printf $H <<'EOF';

/* All non-spacing combining marks, sorted */
enum nsm_marks {
EOF
my $i = 0;
for my $nsm (@NSM) {
  my $n = $nsm;
  $n =~ s/[ -]/_/g;
  printf $H "    NSM_%s,\t/* %x */\n", $n, $NSM_CP[$i];
  $i++;
}
printf $H <<'EOF';
    NSM_LAST
};
EOF

printf $H <<'EOF', scalar @NSM, scalar @NSM;

/* All letters with non-spacing combining marks, sorted.
   The first entry is the NSM, if letters exist.
 */
#ifdef EXTERN_SCRIPTS
extern const uint32_t nsm_letters[][%u];
#else
const uint32_t nsm_letters[][%u] = {
    // clang-format off
EOF
$i = 0;
for my $nsm (@NSM) {
  printf $H "    { ";
  my $j = 0;
  if ($NSM{$nsm}) {
    printf $H "0x%x,\n      ", $NSM_CP[$i];
    for (@{$NSM{$nsm}}) {
      printf $H "0x%x,", $_;
      $j++;
      if ($j % 10 == 0) {
        printf $H "\n      ";
      } else {
        printf $H " ";
      }
    }
  }
  printf $H "0 },\t/* NSM: %s %x */\n", $nsm, $NSM_CP[$i];
  $i++;
}
printf $H <<'EOF';
    // clang-format on
};
#endif
EOF

# assume symlinked
if (-e "roaring.h" && -e "roaring.c") {
    print "Create serialized roaring bitmaps:\n";
    if ($^O =~ /Win32/) {
	system($Config{cc}." mkroar.c -I. -o mkroar.exe");
	system("mkroar.exe mark");
	# ignore vms for now
    } else {
	system($Config{cc}." mkroar.c -I. -o mkroar");
	system("./mkroar mark");
    }
    print "\n";
    my $c = "mark_croar";
    print $H <<'EOF';

// This was just an experiment. It's slower than binary search in ranges.
#ifdef HAVE_CROARING
#  ifndef EXTERN_SCRIPTS
/* generated via mkroar.c */
EOF
    close $H;
    system("xxd -i $c.bin >> $mark_h");
    unlink "$c.bin";
    open $H, ">>", $mark_h or die "appending $mark_h $!";
    print $H <<'EOF';
#  else
extern const unsigned int mark_croar_bin_len;
extern const unsigned char mark_croar_bin[1219]; // checkme on updates
#  endif // EXTERN_SCRIPTS
#endif // HAVE_CROARING
EOF
}

close $H;
chmod 0444, $mark_h;
print "Created mark.h\n";

