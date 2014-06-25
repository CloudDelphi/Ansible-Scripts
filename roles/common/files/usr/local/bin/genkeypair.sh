#!/bin/sh

# Generate self-signed server certificates.  Inspired from
# make-ssl-cert(8).
# XXX: add support for DKIM and OpenSSH
#
# Copyright © 2014 Guilhem Moulin <guilhem@fripost.org>
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

set -ue
PATH=/usr/bin:/bin

# Default values
type=rsa
bits=
hash=sha1

force=
pubkey=pubkey.pem
privkey=privkey.pem

usage() {
    cat >&2 <<- EOF
		Usage: $0 [OPTIONS]
		Generate self-signed server certificates

		Options:
		    -t type:    key type (default: rsa)
		    -b bits:    key length or EC curve (default: 2048 for RSA, 1024 for DSA, secp224r1 for ECDSA)
		    -h digest:  digest algorithm (default: sha1)
		    -n CN:      common name (default: \$(hostname --fqdn)
		    -f force:   overwrite key files if they exist
		    --pubkey:   public key file (default: pubkey.pem)
		    --privkey:  private key file (default: privkey.pem; created with og-rwx)

		Return values:
		    0  The key pair was successfully generated
		    1  The public or private key file exists, and -f is not set
		    2  The key generation failed
	EOF
}

name=$(hostname --fqdn)
while [ $# -gt 0 ]; do
    case "$1" in
        -t) shift; type="$1";;
        -t*) type="${1#-t}";;

        -b) shift; bits="$1";;
        -b*) bits="${1#-b}";;

        -h) shift; hash="$1";;
        -h*) hash="${1#-h}";;

        -n) shift; name="$1";;
        -n*) name="${1#-n}";;

        -f) force=1;;
        --pubkey=*) pubkey="${1#--pubkey=}";;
        --privkey=*) privkey="${1#--privkey=}";;

        --help) usage; exit;;
        *) echo "Unrecognized argument: $1" >&2; exit 2
    esac
    shift;
done

rand=/dev/urandom
case "$type" in
    rsa) genkey=genrsa; genkeyargs="-f4 ${bits:-2048}";;
    dsa) genkey=dsaparam; genkeyargs="-noout -genkey ${bits:-1024}";;
    # See 'openssl ecparam -list_curves' for the list of supported
    # curves. StrongSwan doesn't support explicit curve parameters
    # (however explicit parameters might be required to make exotic
    # curves work with some clients.)
    ecdsa) genkey=ecparam
           genkeyargs="-noout -name ${bits:-secp224r1} -param_enc named_curve -genkey";;
    *) echo "Unrecognized key type: $type" >&2; exit 2
esac

case "$hash" in
    md5|rmd160|sha1|sha224|sha256|sha384|sha512) ;;
    *) echo "Invalid digest algorithm: $hash" >&2; exit 2;
esac

[ ${#name} -le 64 ] || { echo "Hostname too long: $name" >&2; exit 2; }
for file in "$pubkey" "$privkey"; do
    [ -z "$force" -a -s "$file" ] || continue
    echo "Error: File exists: $file" >&2
    exit 1
done

config=$(mktemp) || exit 2
trap 'rm -f "$config"' EXIT
# see /usr/share/ssl-cert/ssleay.cnf
cat >"$config" <<- EOF
	[ req ]
	distinguished_name  = req_distinguished_name
	prompt              = no
	policy			    = policy_anything
	req_extensions      = v3_req
	x509_extensions     = v3_req

	[ req_distinguished_name ]
	commonName          = $name

	[ v3_req ]
	basicConstraints    = critical, CA:FALSE
EOF

# Ensure "$privkey" is created with umask 0077
mv "$(mktemp)" "$privkey" || exit 2
chmod og-rwx "$privkey" || exit 2

openssl $genkey -rand /dev/urandom $genkeyargs >"$privkey" || exit 2
openssl req -config "$config" -new -x509 -days 3650 -"$hash" -key "$privkey" >"$pubkey" || exit 2
