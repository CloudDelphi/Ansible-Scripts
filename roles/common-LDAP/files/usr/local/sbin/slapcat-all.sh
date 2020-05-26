#!/bin/sh

# Usage: slapcat-all.sh DIR
# Save all LDAP databases in DIR: DIR/SUFFIX0.ldif, DIR/SUFFIX1.ldif, ...

set -ue
PATH="/usr/bin:/bin"
export PATH

TARGET="$1"
umask 0077

ldapsearch() {
    command ldapsearch -H "ldapi://" -QY EXTERNAL "$@"
}

backup_database() {
    local base="$1"
    ldapsearch -b "$base" \+ \* >"$TARGET/$base.ldif"
}

backup_database "cn=config"

SUFFIXES="$TARGET/slapd-suffixes"
ldapsearch -LLL -oldif-wrap="no" -b "cn=config" "(&(objectClass=olcDatabaseConfig)(objectClass=olcMdbConfig))" "olcSuffix" >"$SUFFIXES"
sed -n -i "s/^olcSuffix:\\s*//p" "$SUFFIXES"

while IFS= read -r b; do
    [ "${b%,dc=fripost-test,dc=org}" = "$b" ] || continue
    backup_database "$b"
done <"$SUFFIXES"
