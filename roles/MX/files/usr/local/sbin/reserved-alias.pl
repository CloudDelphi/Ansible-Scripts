#!/usr/bin/perl

# Copyright © 2013 Guilhem Moulin <guilhem@fripost.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use warnings;
use strict;
use Net::LDAPI;
use Net::LDAP::Util qw/escape_filter_value ldap_explode_dn escape_dn_value/;
use Authen::SASL;
use Net::SMTP;

if (!@ARGV or grep { $_ eq '-h' or $_ eq '--help' } @ARGV) {
    # Help
    print STDERR "Usage: $0 {original sender} {original recipient} [additional recipient ...]\n";
    print STDERR "\n";
    print STDERR "The message read from the standard input is redirected to 'additional recipient',\n";
    print STDERR "and also forwarded to the domain owner if any. If the 'additional recipient' begins\n";
    print STDERR "with '\@', the localpart of 'original recipient' is prepended.\n";
    print STDERR "\n";
    print STDERR "This is mostly useful to comply to RFC 822 section 6.3 and RFC 2142 section\n";
    print STDERR "4 (to forward mails to 'admin\@' and 'postmaster\@' to the site admin in\n";
    print STDERR "addition to the virtual domain manager).\n";
    exit;
}

# The original sender
my $sender = shift;

# The original recipient
my $orig = shift;
$orig =~ /^(.+)\@([^@]+)$/
    or warn "Warning: Non fully qualified: $orig";
my ($local,$domain) = ($1,$2);

# The new recipient (typically, the admin site)
my @recipients = grep { $_ and $orig ne $_ }
                 # add localparts to domain
                 map { my $x = $_;
                       if ($x =~ /^\@/) {
                         $x = (defined $local and $local ne '') ? $local.$x : undef;
                       }
                       $x
                     }
                 @ARGV;
# Die if we can't deliver to site admins
die "Error: Aborted delivery to '$orig' in attempt to break an alias expansion loop.\n"
    unless @recipients;

if (defined $domain) {
    # Look for the domain owner or postmaster
    my $ldap = Net::LDAPI->new();
    $ldap->bind( sasl => Authen::SASL->new(mechanism => 'EXTERNAL') )
        or die "Error: Couldn't bind";

    my @attrs = ( 'fripostPostmaster', 'fripostOwner' );
    my $mesg = $ldap->search( base => 'fvd='.escape_dn_value($domain).','
                                     .'ou=virtual,o=mailHosting,dc=fripost,dc=org'
                            , scope => 'base'
                            , deref => 'never'
                            , filter => '(&(objectClass=FripostVirtualDomain)'
                                         .'(fvd='.escape_filter_value($domain).')'.
                                        ')'
                            , attrs => \@attrs
                            );
    if ($mesg->code) {
        warn "Warning: ".$mesg->error;
    }
    elsif ($mesg->count != 1) {
        # Note: this may happen for "$mydestination", but these mails
        # are unlikely. We'll get a harmless warning at worst.
        warn "Warning: Something weird happened when looking up domain '".$domain.
             "'. Check your ACL.";
    }
    else {
        my $entry = $mesg->pop_entry() // die "Error: Cannot pop entry.";
        foreach (@attrs) {
            my $v = $entry->get_value($_, asref => 1) or next;
            foreach my $dn (@$v) {
                my $dn2 = ldap_explode_dn($dn, casefold => 'lower');
                my $l = $dn2->[0]->{fvl};
                my $d = $dn2->[1]->{fvd};
                if ($l ne '' and $d ne '') {
                    push @recipients, $l.'@'.$d;
                }
                else {
                    warn "Warning: Invalid DN: $dn"
                }
            }
        }
    }
    $ldap->unbind;
}

my $smtp = Net::SMTP->new( 'localhost:25', Timeout => 1200 );
$smtp->mail($sender);
$smtp->to(@recipients, { Notify => ['FAILURE','DELAY'], SkipBad => 1 });
$smtp->data(<STDIN>);
$smtp->quit;
