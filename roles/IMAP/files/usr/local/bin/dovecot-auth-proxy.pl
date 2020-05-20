#!/usr/bin/perl -T

#----------------------------------------------------------------------
# Dovecot userdb lookup proxy table for user iteration
# Copyright © 2017,2020 Guilhem Moulin <guilhem@fripost.org>
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

use Errno qw/EINTR/;
use Net::LDAPI;
use Net::LDAP::Constant qw/LDAP_CONTROL_PAGED LDAP_SUCCESS/;
use Net::LDAP::Control::Paged ();
use Net::LDAP::Util qw/ldap_explode_dn/;
use Authen::SASL;

my $BASE = "ou=virtual,dc=fripost,dc=org";

# clean up PATH
$ENV{PATH} = join ':', qw{/usr/bin /bin};
delete @ENV{qw/IFS CDPATH ENV BASH_ENV/};

# number of pre-forked servers and maximum requests per worker
my $nProc = 1;
my $maxRequests = 1;
sub server();

# fdopen(3) the file descriptor FD
die "This service must be socket-activated.\n"
    unless defined $ENV{LISTEN_PID} and $ENV{LISTEN_PID} == $$
       and defined $ENV{LISTEN_FDS} and $ENV{LISTEN_FDS} == 1;
open my $S, '+<&=', 3 or die "fdopen: $!";

my @CHILDREN;
for (my $i = 0; $i < $nProc-1; $i++) {
    my $pid = fork() // die "fork: $!";
    if ($pid) {
        push @CHILDREN, $pid;
    } else {
        server(); # child, never return
        exit;
    }
}
server();
waitpid $_ => 0 foreach @CHILDREN;
exit $?;


#############################################################################

sub server() {
    for (my $n = 0; $n < $maxRequests; $n++) {
        accept(my $conn, $S) or do {
            next if $! == EINTR;
            die "accept: $!";
        };

        my $hello = $conn->getline() // '';
        unless ($hello =~ /\AH(\d+)\t(\d+)\t(\d+)(?:\t.*)?\n\z/) {
            warn "Invalid greeting line: $hello\n";
            close $conn or warn "Can't close: $!";
            next;
        }
        # <major-version> <minor-version> <value type>
        unless ($1 == 2 and $2 == 2 and $3 == 0) {
            warn "Unsupported protocol version $1.$2 (or value type $3)\n";
            close $conn or warn "Can't close: $!";
            next;
        }

        my $cmd = $conn->getline() // '';
        if ($cmd =~ /\AI(\d+)\t(\d+)\t(.*)\n\z/) {
            iterate($conn, $1, $2, $3);
        }
        else {
            fail($conn => "Unknown command line: $cmd");
        }
        close $conn or warn "Can't close: $!";
    }
}

sub fail($;$) {
    my ($fh, $msg) = @_;
    $fh->printflush("F\n");
    print STDERR $msg, "\n" if defined $msg;
}

sub dn2user($) {
    my $dn = shift;
    $dn = ldap_explode_dn($dn, casefold => "lower");
    if (defined $dn and $#$dn == 4
            and defined (my $l = $dn->[0]->{fvl})
            and defined (my $d = $dn->[1]->{fvd})) {
        return $l ."@". $d;
    }
}

# list all users (even the inactive ones)
sub iterate($$$$) {
    my ($fh, $flags, $max_rows, $prefix) = @_;
    unless ($flags == 0) {
        fail($fh => "Unsupported iterate flags $flags");
        return;
    }

    my $ldap = Net::LDAPI::->new();
    $ldap->bind( undef, sasl => Authen::SASL::->new(mechanism => "EXTERNAL") )
        or do { fail($fh => "Error: Couldn't bind"); return; };
    my $page = Net::LDAP::Control::Paged::->new(size => 100);

    my $callback = sub($$) {
        my ($mesg, $entry) = @_;
        return unless defined $entry;

        my $dn = $entry->dn();
        if (defined (my $user = dn2user($dn))) {
            $fh->printf("O%s%s\t\n", $prefix, $user);
        } else {
            print STDERR "Couldn't extract username from dn: ", $dn, "\n";
        }
        $mesg->pop_entry;
    };

    my @search_args = (
          base => $BASE,
        , scope => "children"
        , deref => "never"
        , filter => "(objectClass=FripostVirtualUser)"
        , sizelimit => $max_rows
        , control => [$page]
        , callback => $callback
        , attrs => ["1.1"]
    );

    my $cookie;
    while (1) {
        my $mesg = $ldap->search(@search_args);
        last unless $mesg->code == LDAP_SUCCESS;

        my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;
        $cookie = $resp->cookie();
        goto SEARCH_DONE unless defined $cookie and length($cookie) > 0;

        $page->cookie($cookie);
    }

    if (defined $cookie and length($cookie) > 0) {
        fail($fh => "Abnormal exit from LDAP search, aborting");
        $page->cookie($cookie);
        $page->size(0);
        $ldap->search(@search_args);
    }

    SEARCH_DONE:
    $ldap->unbind();
    $fh->printflush("\n");
}
