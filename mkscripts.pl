#!/usr/bin/env perl
# libu8ident - Check unicode security guidelines for identifiers.
# Copyright 2014, 2021, 2022 Reini Urban
# SPDX-License-Identifier: Apache-2.0
#
# Classify and search for the script property https://www.unicode.org/reports/tr24/tr24-32.html
# Implement http://www.unicode.org/reports/tr39/#Mixed_Script_Detection
# Generates the following lists: all_scripts as strings and defines, xid_script,
# nonxid_script, scx, allowed_id, idtype, NF{K,}{C,D}_N, NF{K,}C_M, bidi.
#
# TODO https://www.unicode.org/reports/tr31/
# * More uax31_d1, uax31_r1, uax31_r1b.
#   xid is relevant for NFKC languages (ie python 3), the rest should use id_{start,cont} or
#   better allowed_id, which keeps only recommended scripts.
# * An optimized all-in-one start/cont list for SAFEC23, without Excluded and Limited_Use scripts,
#   with only allowing NFC, with SC and SCX combined. This should be default without
#   user-added scripts (#pragma unicode Braille). Then you need to fallback to the slow lists.
# * More statistics, to check against perf results. E.g. why croaring or eytzinger is not good enough.

use strict;
my $scn = "Scripts.txt";
my $scxn = "ScriptExtensions.txt";
my $pva = "PropertyValueAliases.txt";
my $normp = "DerivedNormalizationProps.txt";
my $corep = "DerivedCoreProperties.txt";
# --
my $idtype = "IdentifierType.txt";
my $idstat = "IdentifierStatus.txt";
for ($scn, $scxn, $pva, $corep, $normp) {
  if (!-e $_) {
    system("wget -N https://www.unicode.org/Public/UNIDATA/$_");
  }
}
for ($idtype, $idstat) {
  if (!-e $_) {
    system("wget -N https://www.unicode.org/Public/security/latest/$_");
  }
}

my (@ucd_version, $from, $to, $sc, $oldto, $oldsc,
    @SC, @SCR, @SCRF, @SCXR, %SC, %scripts, $id);
my ($started, @IDTYPES, @ALLOWED, @IDSTART, @IDCONT, @XIDSTART, @XIDCONT,
    @SAFEC23START, @SAFEC23CONT);
open my $IDTYPE, "<", $idtype or die "$idtype $!";
while (<$IDTYPE>) {
  if (/^#\tIdentifier_Type:/) { $started++; }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; ([\w ]+)\s+#/) {
    ($from, $to, $id) = (hex($1), hex($2), $3);
    push @IDTYPES, [$from, $to, $id];
    # TODO match from-to with @SC ranges
  }
  elsif (/^([0-9A-F]{4,5})\s+; ([\w ]+)\s+#/) {
    ($from, $id) = (hex($1), $2);
    push @IDTYPES, [$from, $from, $id];
  }
}
close $IDTYPE;
# Collapse neighbors. sort the list by ->from
my (@_ID, $oldid);
$oldto = 0;
my %idtype_values = map { $_->[2] => 1 } @IDTYPES;
for my $r (sort { $a->[0] <=> $b->[0] } @IDTYPES) {
  my ($from, $to, $id) = ($r->[0], $r->[1], $r->[2]);
  if (($from != $oldto + 1) or ($oldid ne $id)) { # honor holes
    push @_ID, [$from, $to, $id];
    # $oldsc = $sc;
  } else { # update the range
    my $range = $_ID[$#_ID];
    $range->[1] = $to;
    $_ID[$#_ID] = $range;
  }
  # check if the entry can be merged into the previous. The UCD tracks the history, we don't care
  if ($#_ID - 1 >= 0) {
    my $prev = $_ID[$#_ID - 1];
    my $last = $_ID[$#_ID];
    if ($prev->[1] + 1 >= $last->[0] and $prev->[2] eq $last->[2]) {
      $prev->[1] = $last->[1];
      $prev->[2] = $last->[2];
      pop @_ID;
    }
  }
}
@IDTYPES = @_ID;
undef @_ID;

open my $COREP, "<", $corep or die "$corep $!";
$started = 0;
my $ref;
while (<$COREP>) {
  if (/^# Derived Property: (\w+)/) {
    if ($1 eq 'ID_Start') {
      $ref = \@IDSTART;
      $started = 1;
    }
    elsif ($1 eq 'ID_Continue') {
      $ref = \@IDCONT;
      $started = 1;
    }
    elsif ($1 eq 'XID_Start') {
      $ref = \@XIDSTART;
      $started = 1;
    }
    elsif ($1 eq 'XID_Continue') {
      $ref = \@XIDCONT;
      $started = 1;
    }
    else {
      $started = 0;
    }
  }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; [\w ]+\s+#/) {
    ($from, $to) = (hex($1), hex($2));
    push @$ref, [$from, $to];
  }
  elsif (/^([0-9A-F]{4,5})\s+; [\w ]+\s+#/) {
    $from = hex($1);
    push @$ref, [$from, $from];
  }
}
close $COREP;

open my $IDSTAT, "<", $idstat or die "$idstat $!";
$started = 0;
# already sorted, as there is only one value
while (<$IDSTAT>) {
  if (/^#\tIdentifier_Status:/) { $started++; }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; Allowed\s+#/) {
    push @ALLOWED, [hex($1), hex($2)];
  }
  elsif (/^([0-9A-F]{4,5})\s+; Allowed\s+#/) {
    push @ALLOWED, [hex($1), hex($1)];
  }
  # check if the entry can be merged into the previous. The UCD tracks the history, we don't care
  if ($#ALLOWED - 1 >= 0) {
    my $prev = $ALLOWED[$#ALLOWED - 1];
    my $last = $ALLOWED[$#ALLOWED];
    if ($prev->[1] + 1 >= $last->[0]) {
      $prev->[1] = $last->[1];
      pop @ALLOWED;
    }
  }
}
close $IDSTAT;

sub search {
  my ($cp, $listref) = @_;
  for my $r (@$listref) {
    if ($cp >= $r->[0] and $cp <= $r->[1]) {
      return $r;
    }
  }
  return 0; # not found
}

sub is_allowed {
  my $cp = shift;
  for my $r (@ALLOWED) {
    if ($cp >= $r->[0] and $cp <= $r->[1]) {
      return 1;
    }
  }
  return 0; # not allowed
}

# Restricted: skip Limited_Use, Obsolete, Exclusion, Not_XID, Not_NFKC, Default_Ignorable, Deprecated
# Allowed: keep Recommended, Inclusion
# Maybe allow by request Technical
sub ok_idtype_cp {
  my $cp = shift;
  for my $r (@IDTYPES) {
    if ($cp >= $r->[0] and $cp <= $r->[1]) {
      return 0 if $r->[2] =~ /\b(Limited_Use|Obsolete|Exclusion|Not_XID|Not_NFKC|Uncommon_Use|Default_Ignorable|Deprecated)\b/;
      return 1 if $r->[2] =~ /\b(Recommended|Inclusion|Technical)\b/;
      return 0; # unknown identifier type
    }
  }
  return 0; # not a character
}

sub ok_idtype {
  my $id = shift;
  return 0 if $id =~ /\b(Limited_Use|Obsolete|Exclusion|Not_XID|Not_NFKC|Uncommon_Use|Default_Ignorable|Deprecated)\b/;
  return 1 if $id =~ /\b(Recommended|Inclusion|Technical)\b/;
  return 0; # unknown identifier type
}

# TOOD: generate these 2 lists from the IDTYPES or the webpage.
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
$started = 0; $oldsc = '';
while (<$SC>) {
  if (!$started && /^# Scripts-(\d+)\.(\d+)\.(\d+)\.txt/) {
    @ucd_version = ($1, $2, $3);
  }
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

# needed for the SCX short -> name lookup
my %PVA;
$started = 0;
open my $PVA, "<", $pva or die "$pva $!";
while (<$PVA>) {
  if (/^# Script \(sc\)/) { $started++; }
  if (/^sc ; (\w+?)\s+; (\w+)/) {
    $PVA{$1} = $2; # Zinh is not in SCX
  }
}
close $PVA;

$started = 0;
$oldto = 0; $oldsc = "";
open my $SCX, "<", $scxn or die "$scxn $!";
my $scl;
while (<$SCX>) {
  if (/^# Script_Extensions=/) { $started++; }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; ([\w ]+) #/) {
    ($from, $to, $scl) = (hex($1), hex($2), $3);
  }
  elsif (/^([0-9A-F]{4,5})\s+; ([\w ]+) #/) {
    ($from, $to, $scl) = (hex($1), hex($1), $2);
    if ($from == 0x0345) { # UCD bug
      $from = 0x342;
      $oldto = 0x341; # update the prev. range
    }
  } else {
    #warn $_;
    next;
  }
  # only if the Sc is new or there is a hole
  if (($from != $oldto + 1) or ($oldsc ne $scl) or !@SCXR) {
    # scl is a string, list of short script names
    push @SCXR, [$from, $to, $scl];
    $oldsc = $scl;
  } else { # update the range
    my $range = $SCXR[$#SCXR];
    $range->[1] = $to;
    $SCXR[$#SCXR] = $range;
  }
  $oldto = $to;
}
close $SCX;
# special-case (scx bug in 14), but handled above
#push @SCXR, [0x343, 0x344, 'Grek']; # not Inherited

my $num_scripts = scalar keys %scripts;
printf "%d SC ranges, %d unique scripts", scalar @SCR, $num_scripts;
printf ", %d SCX ranges\n", scalar @SCXR;
die if $num_scripts > 255;

$started = 0;
open my $NORMP, "<", $normp or die "$normp $!";
my ($list, $yes_maybe, @NORM_QC,
    @NFD_QC_N, @NFC_QC_N, @NFC_QC_M, @NFKD_QC_N, @NFKC_QC_N, @NFKC_QC_M);
while (<$NORMP>) {
  # first list
  if (/^# NFD_Quick_Check=No/) { $started++; }
  next unless $started;
  if (/^([0-9A-F]{4,5})\.\.([0-9A-F]{4,5})\s+; (NF\w+_QC); ([NMY]) #/) {
    ($from, $to, $list, $yes_maybe) = (hex($1), hex($2), $3, $4);
  }
  elsif (/^([0-9A-F]{4,5})\s+; (NF\w+_QC); ([NMY]) #/) {
    ($from, $to, $list, $yes_maybe) = (hex($1), hex($1), $2, $3);
  } else {
    #warn $_;
    next;
  }
  no strict 'refs';
  my $name = $list . "_" . $yes_maybe;
  unless (@{$name}) {
    push @NORM_QC, $name;
    print "$name\n";
  }
  push @{$name}, [$from, $to];
}
close $NORMP;

# sort the scripts by ->from
@SCR = sort { $a->[0] <=> $b->[0] } @SCR;
@SCXR = sort { $a->[0] <=> $b->[0] } @SCXR;

# splice l2 into l1
sub merge {
  my ($l1, $l2) = @_;
  my @r = ();
  while (@$l1) {
    my $e1 = $l1->[0];
    if (!@$l2) {
      push @r, $e1;
      shift @$l1;
      next;
    }
    my $e2 = $l2->[0];
    if ($e1->[0] < $e2->[0]) {
      # [0,10,a] + [1,9,b]  => [0,1,a], [1,9,b], [9,10,a]
      # [0,9,a]  + [1,10,b] => [0,1,a], [1,10,b]
      if ($e1->[1] < $e2->[1]) {
        if (@r > 0 and $r[$#r][2] eq $e1->[2] and $r[$#r][1] == $e1->[0] - 1) {
          warn "combine 1 $r[$#r][1] with $e1->[1] $e1->[2]";
          $r[$#r][1] = $e1->[1]; # we can combine it with the last
        } else {
          push @r, $e1;
        }
        shift @$l1;
      } else { # splice e2 int e1
        push @r, [$e1->[0], $e2->[0] - 1, $e1->[2]] if $e1->[0] <= $e2->[0] - 1;
        push @r, [$e2->[0], $e2->[1], $e2->[2], $e1->[2]] if $e2->[0] <= $e2->[1]; # add the old SC also
        if ($e2->[1] + 1 <= $e1->[1]) {
          $l1->[0] = [$e2->[1] + 1, $e1->[1], $e1->[2]];
         } else {
           shift @$l1;
        }
        shift @$l2;
      }
    } else {
      if ($e1->[1] >= $e2->[1]) {
        if ($r[$#r][2] eq $e2->[2] and $r[$#r][1] == $e2->[0] - 1) {
          warn "combine 2 $r[$#r][1] with $e2->[1] $e2->[2]";
          $r[$#r][1] = $e2->[1]; # we can combine it with the last
        } else {
          push @r, $e2;
        }
        shift @$l2;
        shift @$l1; # replace
      } else { # splice
        # [2,10,a] + [1,9,b]  => [0,1,a], [1,9,b], [9,10,a]
        push @r, [$e2->[0], $e2->[1], $e2->[2], $e1->[2]];
        push @r, [$e2->[1] + 1, $e1->[1], $e1->[2]] if $e2->[1] + 1 <= $e1->[1];
        shift @$l1;
        shift @$l2;
      }
    }
    # can we merge the last two? (1DBF, 303C)
    if (@r > 1 && $r[$#r-1][2] eq $r[$#r][2] && $r[$#r-1][1] == $r[$#r]->[0] + 1) {
      warn "combine end $r[$#r-1][1] with $r[$#r][0] $r[$#r][2]";
      $r[$#r-1][1] = $r[$#r]->[1];
      shift @r;
    }
  }
  while (my $e2 = shift @$l2) {
    push @r, $e2;
  }
  return @r;
}

$oldto = 0;
# Collapse neighbors, generate a fast SCRF variant without holes.
my @_SCR;
undef $oldsc;
my $oldscf = '';
for my $r (@SCR) {
  ($from, $to, $sc) = ($r->[0], $r->[1], $r->[2]);
  # the full list, with all holes.
  if (($from != $oldto + 1) or ($oldsc ne $sc)) { # honor holes
    push @_SCR, [$from, $to, $sc];
    $oldsc = $sc;
  } else { # update the range
    my $range = $_SCR[$#_SCR];
    $range->[1] = $to;
    $_SCR[$#_SCR] = $range;
  }
  $oldto = $to;
  # now the faster variant
  if ($oldscf ne $sc or !@SCRF) { # ignore holes
    push @SCRF, [$from, $to, $sc];
    $oldscf = $sc;
  } else { # update the range
    my $range = $SCRF[$#SCRF];
    $range->[1] = $to;
    $SCRF[$#SCRF] = $range;
  }
}
@SCR = @_SCR;

my $i = 0;
my %scname;
for my $sc (@recommended) {
  $SC{$sc} = $i;
  $scname{$i} = $sc;
  $i++;
}
my %other = map {$_ => 1} @recommended, @limited;
for my $sc (sort keys %scripts) {
  unless ($other{$sc}) {
    $SC{$sc} = $i;
    $scname{$i} = $sc;
    $i++;
  }
}
for my $sc (@limited) {
  $SC{$sc} = $i;
  $scname{$i} = $sc;
  $i++;
}
$i--;
# find single script SCX's (e.g. Han as Common)
my @single_scx = grep {$_->[2] !~ / /} @SCXR;
for (@single_scx) {
  $_->[2] = $scname{$SC{$PVA{$_->[2]}}}; # expand short to long script name
}
# and merge them into @SC, replacing Common or Inherited
if (@single_scx) {
  @SCR = merge(\@SCR, \@single_scx);
  @SCRF = merge(\@SCRF, \@single_scx);
}

# TODO: Optimized SAFEC23 start/cont lists, with enforced NFC. i.e. disallow scripts,
# and combining marks which do not compose to NFC. Combine SC with SCX.

open my $H, ">", "scripts.h" or die "writing scripts.h $!";
print $H <<"EOF";
/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   generated by mkscripts.pl, do not modify.
   UNICODE version $ucd_version[0].$ucd_version[1]
*/

struct sc {
  uint32_t from;
  uint32_t to;
  uint8_t scr; // index
};

struct scx {
  uint32_t from;
  uint32_t to;
  const char *list; // indices
};

struct range_bool {
  uint32_t from;
  uint32_t to;
};

struct range_short {
  uint32_t from;
  uint32_t to;
  uint16_t types;
};

/* Provide a mapping of the $num_scripts Script properties to an index byte.
   Sorted into usages.
 */
#ifndef EXT_SCRIPTS
const char *const all_scripts[] = {
    // clang-format off
    // Recommended Scripts (not need to add them)
    // https://www.unicode.org/reports/tr31/#Table_Recommended_Scripts
EOF
$i = 0;
my $defines = "";
for my $sc (@recommended) {
  my $n = 10 - length($sc);
  my $ws = $n > 0 ? " " x $n : "";
  $defines .= sprintf("#define SC_%s%s %d\n", $sc, $ws, $i);
  printf $H "    \"%s\",\n", $sc;
  $i++;
}
$defines .= "#define FIRST_EXCLUDED_SCRIPT $i\n";
print $H <<"EOF";
    // Excluded Scripts (but can be added expliclitly)
    // https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers
EOF
for my $sc (sort keys %scripts) {
  unless ($other{$sc}) {
    my $n = 10 - length($sc);
    my $ws = $n > 0 ? " " x $n : "";
    $defines .= sprintf("#define SC_%s%s %d\n", $sc, $ws, $i);
    printf $H "    \"%s\",\n", $sc;
    $i++;
  }
}
$defines .= "#define FIRST_LIMITED_USE_SCRIPT $i\n";
print $H <<"EOF";
    // Limited Use Scripts
    // https://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts
EOF
for my $sc (@limited) {
  my $n = 10 - length($sc);
  my $ws = $n > 0 ? " " x $n : "";
  $defines .= sprintf("#define SC_%s%s %d\n", $sc, $ws, $i);
  printf $H "    \"%s\",\n", $sc;
  $i++;
}
$i--;
printf $H <<"EOF", $i;
    // clang-format on
};
#else
extern const char *const all_scripts[%u];
#endif

#define FIRST_RECOMMENDED_SCRIPT 0
// clang-format off
EOF
print $H $defines;

printf $H <<"EOF", $i, scalar @SCR;
// clang-format on
#define LAST_SCRIPT %u

#if !defined DISABLE_CHECK_XID && !defined ENABLE_CHECK_XID
// The slow variant without U8ID_CHECK_XID. Add all holes for non-identifiers or
// non-codepoints. Not needed with U8ID_CHECK_XID or when the parser checks
// all XID's properly.
#  ifdef EXT_SCRIPTS
extern const struct sc xid_script_list[%u];
#  else
const struct sc xid_script_list[] = {
    // clang-format off
EOF
my ($b, $s);
for my $r (@SCR) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X, %d},\t// %s", $r->[0], $r->[1], $SC{$r->[2]}, $r->[2];
  if (@$r == 4) {
    printf $H ", originally SC %s\n", $r->[3];
  } else {
    printf $H "\n";
  }
};
printf $H <<"EOF", $b, $s, scalar(@SCRF);
    // clang-format on
}; // %u ranges, %u single codepoints
#  endif
#endif // DISABLE_CHECK_XID

// The fast variant with U8ID_CHECK_XID. No holes for non-identifiers or
// non-codepoints needed, as the parser or our XID check already disallowed such
// codepoints.
#ifdef EXT_SCRIPTS
extern const struct sc nonxid_script_list[%u];
#else
const struct sc nonxid_script_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@SCRF) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X, %d},\t// %s", $r->[0], $r->[1], $SC{$r->[2]}, $r->[2];
  if (@$r == 4) {
    printf $H ", from SC %s\n", $r->[3];
  } else {
    printf $H "\n";
  }
};
printf $H <<"EOF", $b, $s;
    // clang-format on
}; // %u ranges, %u single codepoints
#endif

// Fixed up SCX list: Replaced SC Common/Inherited with a single SCX
// TODO: Remove all Limited Use SC's from the list on hardcoded profiles 3-5
#ifndef EXT_SCRIPTS
const struct scx scx_list[] = {
    // clang-format off
EOF
my $size;
($b, $s, $size) = (0, 0, scalar @SCXR);
for my $r (@SCXR) {
  my $code;
  my @list = split " ", $r->[2];
  for my $short (@list) {
    my $long = @list == 1 ? $short : $PVA{$short};
    warn "Wrong $short at U+".sprintf("%X",$r->[0]) unless $SC{$long};
    $code .= sprintf("\\x%02x", $SC{$long});
  }
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  if (@list == 1) {
    $size--;
    printf $H "    // {0x%04X, 0x%04X, \"%s\"},\t// %s, moved to sc proper\n", $r->[0], $r->[1], $code, $r->[2];
  } else {
    printf $H "    {0x%04X, 0x%04X, \"%s\"},\t// %s\n", $r->[0], $r->[1], $code, $r->[2];
  }
};
printf $H <<"EOF", $b, $s, $size;
    // clang-format on
}; // %u ranges, %u single codepoints
#else
extern const struct scx scx_list[%u];
#endif

#ifndef DISABLE_CHECK_XID
// Allowed scripts from IdentifierStatus.txt.
#  ifndef EXT_SCRIPTS
const struct range_bool allowed_id_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@ALLOWED) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
};
printf $H <<"EOF", $b, $s, scalar(@ALLOWED);
    // clang-format on
}; // %u ranges, %u single codepoints
#  else
extern const struct range_bool allowed_id_list[%u];
#  endif

// TR31 ID_Start
#  ifndef EXT_SCRIPTS
const struct range_bool id_start_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@IDSTART) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
};
printf $H <<"EOF", $b, $s;
    // clang-format on
}; // %u ranges, %u single codepoints

const struct range_bool id_cont_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@IDCONT) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
};
printf $H <<"EOF", $b, $s, scalar(@IDSTART), scalar(@IDCONT);
    // clang-format on
}; // %u ranges, %u single codepoints
#  else
extern const struct range_bool id_start_list[%u];
extern const struct range_bool id_cont_list[%u];
#  endif

// If you use NFKC you'd need the xid lists instead
// NFKC has many special cases, and does not roundtrip.
#  ifndef EXT_SCRIPTS
const struct range_bool xid_start_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@XIDSTART) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
};
printf $H <<"EOF", $b, $s;
    // clang-format on
}; // %u ranges, %u single codepoints

const struct range_bool xid_cont_list[] = {
    // clang-format off
EOF
($b, $s) = (0, 0);
for my $r (@XIDCONT) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
};
printf $H <<"EOF", $b, $s, scalar(@XIDSTART), scalar(@XIDCONT);
    // clang-format on
}; // %u ranges, %u single codepoints
#  else
extern const struct range_bool xid_start_list[%u];
extern const struct range_bool xid_cont_list[%u];
#  endif

// IdentifierType bit-values
enum u8id_idtypes {
EOF
$i = 1;
my %idtype_keys;
for my $s (keys %idtype_values) {
  for (split(" ", $s)) {
    $idtype_keys{$_} = 1;
  }
}
for my $s (sort keys %idtype_keys) {
  printf $H "  U8ID_%s = %u,\n", $s, $i;
  $i *= 2;
};
print $H <<"EOF";
};

//#if 0
/* IdentifierType
   Restricted: skip Limited_Use, Obsolete, Exclusion, Not_XID, Not_NFKC,
   Default_Ignorable, Deprecated

   Allowed: keep Recommended, Inclusion
   Maybe allow by request Technical
*/
#  ifndef EXT_SCRIPTS
const struct range_short idtype_list[] = {
    // clang-format off
EOF
sub idtype_bits {
  my $s = shift;
  my $ret = "";
  for (split " ", $s) {
    $ret .= " | U8ID_$_";
  }
  substr($ret, 3);
}
($b, $s) = (0, 0);
for my $r (@IDTYPES) {
  if ($r->[0] == $r->[1]) {
    $s++;
  } else {
    $b++;
  }
  printf $H "    {0x%04X, 0x%04X, %s},\n", $r->[0], $r->[1], idtype_bits($r->[2]);
};
printf $H <<"EOF", $b, $s, scalar(@IDTYPES);
    // clang-format on
}; // %u ranges, %u single codepoints
#  else
extern const struct range_short idtype_list[%u];
#  endif

#endif // DISABLE_CHECK_XID

// CROARING uses different lists
#if !defined USE_NORM_CROAR || defined PERF_TEST
EOF

# for maybe_normalize
#   MARK: 1963 mark characters (Combining, Overlay, ...) \p{IsM}
#   DECOMPOSED_REST: The remaining 869 non-mark and non-hangul normalizables.
# but we just use the pre-prepared UCD DerivedNormalizationProps, optimized for each
# normalization:
# @NFD_QC_N, @NFC_QC_N, @NFC_QC_M, @NFKD_QC_N, @NFKC_QC_N, @NFKC_QC_M;

for my $name (@NORM_QC) {
  my ($NORM, $M) = ($name =~ /^(NF.+)_QC_(.)$/);
  my $maybe = $M eq 'M' ? 'Maybe' : $M eq 'N' ? 'No' : 'Yes';
  my $list = $NORM . "_" . $M;
  no strict 'refs';
  printf $H <<'EOF', $NORM, $maybe, $NORM, $list, scalar(@{$name}), $list;

// %s_Quick_Check=%s
#  if !defined U8ID_NORM || U8ID_NORM == %s
#    ifdef EXT_SCRIPTS
extern const struct range_bool %s_list[%u];
#    else
const struct range_bool %s_list[] = {
    // clang-format off
EOF
  ($b, $s) = (0, 0);
  for my $r (@{$name}) {
    if ($r->[0] == $r->[1]) {
      $s++;
    } else {
      $b++;
    }
    printf $H "    {0x%04X, 0x%04X},\n", $r->[0], $r->[1];
  };
  printf $H <<'EOF', $b, $s;
    // clang-format on
}; // %u ranges, %u single codepoints
#    endif
#  endif
EOF
}
printf $H <<'EOF';
#endif // USE_NORM_CROAR

// Bidi formatting characters for reordering attacks.
// Only valid with RTL scripts, such as Hebrew and Arabic.
#ifdef EXT_SCRIPTS
extern const struct range_bool bidi_list[2];
#else
const struct range_bool bidi_list[] = {
    // clang-format off
    { 0x202A, 0x202E }, // LRE, RLE, PDF, LRO, RLO
    { 0x2066, 0x2069 }, // LRI, RLI, FSI, PDI
    // clang-format on
};
#endif
EOF
close $H;

# patch our header
my $inc = "include/u8ident.h";
open my $INC, "<", $inc or die "$inc $!";
while (<$INC>) {
  if (/^#define U8IDENT_UNICODE_VERSION (\d+)/) {
    my $version = $1;
    if ($version != $ucd_version[0]) {
      close $INC;
      patch_ucd_major($inc, $ucd_version[0]);
      last;
    }
  }
}
close $INC;

sub patch_ucd_major {
  my ($inc, $version) = @_;
  return unless $version;
  open my $OLD, "<", $inc or die "$inc $!";
  open my $NEW, ">", "$inc.new" or die "$inc.new $!";
  while (<$OLD>) {
    if (/^(#define U8IDENT_UNICODE_VERSION )(\d+)/) {
      print $NEW "$1 $version\n";
    } else {
      print $NEW $_;
    }
  }
  close $OLD, $NEW;
  rename $inc, "$inc.bak";
  rename "$inc.new", $inc;
}
