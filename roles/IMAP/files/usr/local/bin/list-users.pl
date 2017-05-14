#!/usr/bin/perl

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

use warnings;
use strict;
use Net::LDAPI;
use Net::LDAP::Util qw/ldap_explode_dn escape_dn_value/;
use Authen::SASL;

my $BASE = 'ou=virtual,dc=fripost,dc=org';

my $LDAP = Net::LDAPI::->new();
$LDAP->bind( undef, sasl => Authen::SASL::->new(mechanism => 'EXTERNAL') )
    or die "Error: Couldn't bind";

my $mesg = $LDAP->search( base => $BASE, scope => 'children', deref => 'never'
                        , filter => '(objectClass=FripostVirtualUser)'
                        , attrs => ['1.1']
                        );
die $mesg->error if $mesg->code;

while (defined (my $entry = $mesg->pop_entry())) {
    my $dn = $entry->dn() // next;
    $dn = ldap_explode_dn($dn, casefold => 'lower');
    next unless defined $dn and $#$dn == 4;
    my $l = $dn->[0]->{fvl} // next;
    my $d = $dn->[1]->{fvd} // next;
    printf "%s@%s\n", $l, $d;
}

$LDAP->unbind;
