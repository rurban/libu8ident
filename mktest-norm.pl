#!/usr/bin/env perl
use Unicode::Normalize qw(NFC NFKC NFD NFKD FCD FCC);
use Encode;
sub wstr($) {
  join('',map{sprintf'\x%02x',$_} unpack 'W*', encode_utf8 $_[0]);
}
binmode *STDOUT, ":utf8";
# all NFC letters different from NFKC
# unichars -a '\pL' 'NFC ne NFKC'
# e.g. U+1C5 U+140

for ("Cafe\x{301}", "Caf\x{e9}",
     "\x{1f87}", "\x{03B1}\x{0314}\x{0342}\x{0345}",
     "\x{1c5}\x{140}", "D\x{17e}l\x{b7}"
  )
{
  #"\xe1\xbe\x87"
  print "$_ [",wstr($_),"]:\n";
  printf "NFC:  %s [%s]\n", NFC($_), wstr(NFC($_));
  printf "NFKC: %s [%s]\n", NFKC($_), wstr(NFKC($_));
  printf "FCC:  %s [%s]\n", FCC($_), wstr(FCC($_));
  printf "NFD:  %s [%s]\n", NFD($_), wstr(NFD($_));
  printf "NFKD: %s [%s]\n", NFKD($_), wstr(NFKD($_));
  printf "FCD:  %s [%s]\n", FCD($_), wstr(FCD($_));
  print "\n";
}
