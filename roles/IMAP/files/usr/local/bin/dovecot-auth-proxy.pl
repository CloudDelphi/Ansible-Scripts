#!/usr/bin/perl

#----------------------------------------------------------------------
# Dovecot userdb lookup proxy table for user iteration
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

# clean up PATH
$ENV{PATH} = join ':', qw{/usr/bin /bin};
delete @ENV{qw/IFS CDPATH ENV BASH_ENV/};

# number of pre-forked servers
my $nProc = 1;
sub server();

# fdopen(3) the file descriptor FD
die "This service must be socket-activated.\n"
    unless defined $ENV{LISTEN_PID} and $ENV{LISTEN_PID} == $$
       and defined $ENV{LISTEN_FDS} and $ENV{LISTEN_FDS} == 1;
open my $S, '+<&=', 3 or die "fdopen: $!";

do {
    my $dir = (getpwnam('vmail'))[7] // die "No such user: vmail";
    $dir .= '/virtual';
    chdir($dir) or die "chdir($dir): $!";
};

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
    for (my $n = 0; $n < 1; $n++) {
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
        unless ($1 == 2 and $2 == 1 and $3 == 0) {
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
    warn "$msg\n" if defined $msg;
}

# list all users, even the inactive ones
sub iterate($$$$) {
    my ($fh, $flags, $max_rows, $prefix) = @_;
    unless ($flags == 0) {
        fail($fh => "Unsupported iterate flags $flags");
        return;
    }

    opendir my $dh, '.' or do {
        fail($fh => "opendir: $!");
        return;
    };
    my $count = 0;
    while (defined (my $d = readdir $dh)) {
        next if $d eq '.' or $d eq '..';
        opendir my $dh, $d or do {
            fail($fh => "opendir: $!");
            return;
        };
        while (defined (my $l = readdir $dh) and ($max_rows <= 0 or $count < $max_rows)) {
            next if $l eq '.' or $l eq '..';
            my $user = $l.'@'.$d;
            next unless $user =~ /\A[a-zA-Z0-9\.\-_@]+\z/; # skip invalid user names
            $fh->printf("O%s%s\t\n", $prefix, $user);
            $count++;
        }
        closedir $dh or warn "closedir: $!";
    }
    closedir $dh or warn "closedir: $!";

    $fh->printflush("\n");
}
