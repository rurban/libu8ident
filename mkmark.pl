#!/usr/bin/env perl
# libu8ident - Check unicode security guidelines for identifiers.
# Copyright 2014, 2021 Reini Urban
# SPDX-License-Identifier: Apache-2.0
#
# Create mark.h Combining_Mark (Mc | Me | Mn)

use strict;
use Config;
my $ucd = "UnicodeData.txt";
if (!-e $ucd) {
  system("wget -N https://www.unicode.org/Public/UNIDATA/$ucd");
}

my $mark_h = "mark.h";
my @MARK;
open my $UCD, "<", $ucd or die "$ucd $!";
my ($from, $to, $oldto);
while (<$UCD>) {
  my @l = split ';';
  my $mark = @l[2];
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
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   All Combining_Mark (Mc | Me | Mn)
   Generated by mkmark.pl, do not modify.
*/

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

