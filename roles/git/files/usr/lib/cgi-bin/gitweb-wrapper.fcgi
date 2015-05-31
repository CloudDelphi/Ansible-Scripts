#!/usr/bin/perl
# gitweb.cgi wrapper that fixes the UTF-8 problem with fastcgi

# Local redefinition of FCGI::Stream::PRINT
use Encode;
use FCGI;

our $enc = Encode::find_encoding('UTF-8');
our $org = \&FCGI::Stream::PRINT;
no warnings 'redefine';

local *FCGI::Stream::PRINT = sub {
  my @OUTPUT = @_;
  for (my $i = 1; $i < @_; $i++) {
    $OUTPUT[$i] = $enc->encode($_[$i], Encode::FB_CROAK|Encode::LEAVE_SRC);
  }
  @_ = @OUTPUT;
  goto $org;
};

# Execute original script
do "/usr/lib/cgi-bin/gitweb.cgi";
