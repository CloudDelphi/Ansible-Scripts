#!/usr/bin/perl -T

#----------------------------------------------------------------------
# socketmap lookup table returning the SASL login name(s) owning a given
# sender address
# Copyright © 2017 Guilhem Moulin <guilhem@fripost.org>
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
#----------------------------------------------------------------------

use warnings;
use strict;

use Errno 'EINTR';
use Socket qw/PF_UNIX SOCK_STREAM SHUT_RDWR/;

use Net::LDAPI ();
use Net::LDAP::Util qw/ldap_explode_dn escape_dn_value escape_filter_value/;
use Net::LDAP::Constant qw/LDAP_NO_SUCH_OBJECT/;
use Authen::SASL ();

# clean up PATH
$ENV{PATH} = join ':', qw{/usr/bin /bin};
delete @ENV{qw/IFS CDPATH ENV BASH_ENV/};

my $nProc      = 2;                        # number of pre-forked servers
my $POSTMASTER = 'postmaster@fripost.org'; # returned for forbidden envelope sender addresses

my $BASEDN  = 'ou=virtual,dc=fripost,dc=org';
my $BUFSIZE = 65536; # try to read that many bytes at the time
my $LDAPI   = 'ldapi://%2Fvar%2Fspool%2Fpostfix-msa%2Fprivate%2Fldapi/';
sub server();


# fdopen(3) the file descriptor FD
die "This service must be socket-activated.\n"
    unless defined $ENV{LISTEN_PID} and $ENV{LISTEN_PID} == $$
       and defined $ENV{LISTEN_FDS} and $ENV{LISTEN_FDS} == 1;
open my $S, '+<&=', 3 or die "fdopen: $!";

for (my $i = 0; $i < $nProc-1; $i++) {
    my $pid = fork() // die "fork: $!";
    unless ($pid) {
        server(); # child, never return
        exit;
    }
}
server();


#############################################################################

sub server() {
    while(1) {
        accept(my $conn, $S) or do {
            # try again if accept(2) was interrupted by a signal
            next if $! == EINTR;
            die "accept: $!";
        };
        my $reply = process_request($conn);

        # encode the reply as a netstring and send it back
        # https://cr.yp.to/proto/netstrings.txt
        $reply = length($reply).':'.$reply.',';
        my $len = length($reply);

        for (my $i = 0; $i < $len;) {
            my $n = syswrite($conn, $reply, $len-$i, $i) // do {
                warn "Can't write: $!";
                last;
            };
            $i += $n;
        }
        close $conn or warn "Can't close: $!";
    }
}

sub process_request($) {
    my $conn = shift;
    my ($buf, $offset) = (undef, 0);

    # keep reading until the request length is determined
    do {
        my $n = sysread($conn, $buf, $BUFSIZE, $offset) // return "TEMP can't read: $!";
        return "TEMP EOF" if $n == 0;
        $offset += $n;
    } until ($buf =~ /\A(0|[1-9][0-9]*):/);

    # keep reading until the whole request is buffered
    my $strlen = length("$1") + 1; # [len]":"
    my $len = $strlen + $1 + 1;    # [len]":"[string]","
    while ($offset < $len) {
        my $n = sysread($conn, $buf, $BUFSIZE, $offset) // return "TEMP can't read: $!";
        return "TEMP EOF" if $n == 0;
        $offset += $n;
    }

    # requests are of the form $name <space> $key, cf. socketmap_table(5)
    my $i = index($buf, ' ', $strlen);
    return "TEMP invalid input: $buf" unless $i > $strlen and substr($buf,-1) eq ',';
    my $name = substr($buf, $strlen, $i-$strlen);
    my $key = substr($buf, $i, -1);
    return "TEMP invalid name: $name" unless $name eq 'sender_login';

    $key =~ /\A(.+)@([^\@]+)\z/ or return "NOTFOUND "; # invalid sender address
    my ($localpart, $domainpart) = ($1, $2);

    my $ldap = Net::LDAPI::->new( $LDAPI )
        // return "TEMP couldn't create Net::LDAPI object";
    $ldap->bind( undef, sasl => Authen::SASL::->new(mechanism => 'EXTERNAL') )
        or return "TEMP LDAP: couldn't bind";

    my $reply = lookup_sender($ldap, $localpart, $domainpart);
    $ldap->unbind();
    return $reply;
}

sub lookup_sender($$$) {
    my ($ldap, $l, $d) = @_;

    my $filter = '(&(objectClass=FripostVirtualDomain)(fvd='.escape_filter_value($d).'))';
    my $mesg = $ldap->search( base => $BASEDN, scope => 'one', deref => 'never'
                            , filter => $filter
                            , attrs => [qw/objectClass fripostOwner fripostPostmaster/]
                            );
    return "TEMP LDAP error: ".$mesg->error() if $mesg->code;
    my $entry = $mesg->pop_entry() // return "NOTFOUND "; # not a domain we know
    return "TEMP LDAP error: multiple entry founds" if defined $mesg->pop_entry(); # sanity check

    # domain postmasters are allowed to use any sender address
    my @logins = $entry->get_value('fripostPostmaster', asref => 0);
    my @owners = $entry->get_value('fripostOwner', asref => 0);

    if (grep { $_ eq 'FripostVirtualAliasDomain' } $entry->get_value('objectClass', asref => 0)) {
        # so are alias domain owners
        push @logins, @owners;
    } else {
        my $dn = 'fvd='.escape_dn_value($d).','.$BASEDN;
        my $filter = '(&(|(objectClass=FripostVirtualAlias)(objectClass=FripostVirtualList)(objectClass=FripostVirtualUser))(fvl='.escape_filter_value($l).'))';
        my $mesg = $ldap->search( base => $dn, scope => 'one', deref => 'never'
                                , filter => $filter
                                , attrs => [qw/objectClass fripostOwner/]
                                );
        unless ($mesg->code == 0 and defined ($entry = $mesg->pop_entry())) {
            # domains owners are allowed to use any unkwown localpart as sender address
            push @logins, @owners;
        } else {
            return "TEMP LDAP error: multiple entry founds" if defined $mesg->pop_entry(); # sanity check
            if (grep { $_ eq 'FripostVirtualUser' } $entry->get_value('objectClass', asref => 0)) {
                push @logins, $entry->dn();
            } else {
                # alias/list owners can use the address as sender, and so are the domains owners
                push @logins, @owners, $entry->get_value('fripostOwner', asref => 0);
            }
        }
    }

    # convert DNs to SASL login names
    my %logins;
    foreach my $dn (@logins) {
        next unless defined $dn;
        $dn = ldap_explode_dn($dn, casefold => 'lower');
        next unless defined $dn and $#$dn == 4;
        my $l = $dn->[0]->{fvl} // next;
        my $d = $dn->[1]->{fvd} // next;
        $logins{$l.'@'.$d} = 1;
    }

    # if the entry is found in LDAP but doesn't have an owner, only
    # $POSTMASTER is allowed to use it as sender address
    my $reply = %logins ? join(',', keys %logins) : $POSTMASTER;
    return "OK $reply";
}
