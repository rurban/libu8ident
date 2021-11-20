#!/usr/bin/env perl
# libu8ident - Follow unicode security guidelines for identifiers.
# Copyright 2014, 2021 Reini Urban
# Apache LICENSE
#
# Classify and search for the script property https://www.unicode.org/reports/tr24/tr24-32.html
# Implement http://www.unicode.org/reports/tr39/#Mixed_Script_Detection

use strict;
my $scn = "Scripts.txt";
my $scxn = "ScriptExtensions.txt";
if (!-e $scn) {
  system("wget -N https://www.unicode.org/Public/UNIDATA/Scripts.txt");
}
if (!-e $scxn) {
  system("wget -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt");
}

# http://www.unicode.org/reports/tr31/#Table_Recommended_Scripts
my @recommended = qw(
  Common Inherited Latin Arabic Armenian Bengali Bopomofo Cyrillic
  Devanagari Ethiopic Georgian Greek Gujarati Gurmukhi Hangul Han Hebrew
  Hiragana Katakana Kannada Khmer Lao Malayalam Myanmar Oriya
  Sinhala Tamil Telugu Thaana Thai Tibetan);

#All Limited Use Scripts are disallowed:
#http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts
my @limited = qw(
  Adlam Balinese Bamum Batak Canadian_Aboriginal Chakma Cham Cherokee
  Hanifi_Rohingya Javanese Kayah_Li Lepcha Limbu Lisu Mandaic
  Meetei_Mayek Miao New_Tai_Lue Newa Nko Nyiakeng_Puachue_Hmong Ol_Chiki
  Osage Saurashtra Sundanese Syloti_Nagri Syriac Tai_Le Tai_Tham
  Tai_Viet Tifinagh Vai Wancho Yi Unknown);
open my $SC, "<", $scn or die "$scn $!";
open my $SCX, "<", $scxn or die "$scxn $!";
my ($started, $from, $to, $sc, $oldto, $oldsc, @SC, @SCR, @SCXR, %SC, %scripts, $sc);
while (<$SC>) {
  if (/^0000/) { $started++; }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; (\w+) #/) {
    ($from, $to, $sc) = (hex($1), hex($2), $3);
  }
  elsif (/^([0-9A-F]{4,5})\s+; (\w+) #/) {
    ($from, $to, $sc) = (hex($1), hex($1), $2);
  } else {
    #warn $_;
    next;
  }
  # only if the Sc is new or there is a hole
  if (($from != $oldto + 1) or ($oldsc ne $sc)) { 
    push @SCR, [$from, $to, $sc];
    $scripts{$sc}++;
    $oldsc = $sc;
  } else { # update the range
    my $range = $SCR[$#SCR];
    $range->[1] = $to;
    $SCR[$#SCR] = $range;
  }
  $oldto = $to;
}
close $SC;
my $num_scripts = scalar keys %scripts;
printf "%d ranges, %d unique scripts", scalar @SCR, $num_scripts;
die if $num_scripts > 255;

open my $H, ">", "scripts.h" or die "writing scripts.h $!";
print $H <<"EOF";
/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Follow unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   Apache LICENSE

   generated by mkscripts.pl, do not modify.
*/

struct sc {
  uint32_t from;
  uint32_t to;
  uint8_t  scr; // index
};

struct scx {
  uint32_t from;
  uint32_t to;
  uint8_t *list; // indices
};

/* Provide a mapping of the $num_scripts Script properties to an index byte.
   Sorted into usages.
 */
const char* const all_scripts[] = {
#define FIRST_RECOMMENDED_SCRIPT 0
EOF
my $i = 0;
for my $sc (@recommended) {
  my $ws = " " x (10-length($sc));
  $SC{$sc} = $i;
  printf $H "#define SC_%s%s %d\n", $sc, $ws, $i;
  printf $H "  \"%s\",\n", $sc, $i;
  $i++;
}
print $H <<"EOF";
#define FIRST_NOT_RECOMMENDED_SCRIPT $i
  // Not Recommended Scripts (but can to be declared expliclitly)
EOF
my %other = map {$_ => 1} @recommended, @limited;
for my $sc (keys %scripts) {
  unless ($other{$sc}) {
    my $ws = " " x (10-length($sc));
    $SC{$sc} = $i;
    printf $H "#define SC_%s%s %d\n", $sc, $ws, $i;
    printf $H "  \"%s\",\n", $sc, $i;
    $i++;
  }
}
print $H <<"EOF";
#define FIRST_LIMITED_USE_SCRIPT $i
  // Limited Use Scripts
EOF
for my $sc (@limited) {
  my $ws = " " x (10-length($sc));
  $SC{$sc} = $i;
  printf $H "#define SC_%s%s %d\n", $sc, $ws, $i;
  printf $H "  \"%s\",\n", $sc, $i;
  $i++;
}
$i--;
print $H <<"EOF";
#define LAST_SCRIPT $i
};

const struct sc script_list[] = {
EOF
for my $r (@SCR) {
  printf $H "  {0x%04X, 0x%04X, %d},\t// %s\n", $r->[0], $r->[1], $SC{$r->[2]}, $r->[2];
};
print $H <<"EOF";
};
EOF
close $H;
