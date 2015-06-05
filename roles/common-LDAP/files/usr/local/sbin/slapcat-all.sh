#!/bin/sh

# Usage: slapcat-all.sh DIR
# Save all LDAP databases in DIR: DIR/0.ldif, DIR/1.ldif, ...

set -ue
PATH=/usr/sbin:/sbin:/usr/bin:/bin

target="$1"
umask 0077

prefix=slapd-
slapcat -n0 -l"$target/${prefix}0.ldif"
n=$(grep -Ec '^dn:\s+olcDatabase={[1-9][0-9]*}' "$target/${prefix}0.ldif")

while [ $n -gt 0 ]; do
    slapcat -n$n -l"$target/${prefix}$n.ldif"
    n=$(( $n - 1 ))
done
