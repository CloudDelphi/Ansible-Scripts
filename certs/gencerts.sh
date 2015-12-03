#!/bin/sh

set -ue
PATH=/usr/bin:/bin

if [ -n "${GNUPGBIN:-}" ]; then
    GPG="$GNUPGBIN"
elif [ -x /usr/bin/gpg2 ]; then
    GPG=/usr/bin/gpg2
else
    GPG=gpg
fi
GPG_OPTS='--no-auto-check-trustdb --batch --no-verbose --yes'

usage() {
    echo "Usage: $0 /path/to/certs.asc" >&2
    exit 1
}

x509fpr() {
    local msg="$1" host cert h t
    host="${msg%%,*}"; host="${msg%% *}"
    cert="$DIR/${host%%:*}.pem"
    [ "$typ" = mdwn ] && { echo; echo "    $msg"; echo; } || echo "    $msg"
    for t in X.509 PKey; do
        for h in sha1 sha256; do
            [ "$t" = PKey ] && echo -n "$t  $h" || echo -n "$t $h"
            for i in $(seq 1 $((7 - ${#h}))); do echo -n ' '; done
            if [ "$t" = PKey ]; then
                openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -"$h" -c
            else
                openssl x509 -noout -fingerprint -"$h"
            fi <"$cert" | sed -nr 's/^[^=]+=\s*//p'
        done
    done | sed -r "s/(\S+)(.*)/$indent\1\U\2/"
}

sshfpr() {
    local msg="$1" host t h fpr
    host="${msg%%,*}"; host="${msg%% *}"; host="${host#*@}"
    [ "$typ" = mdwn ] && { echo; echo "    $msg"; echo; } || echo "    $msg"
    [ "${host#*:}" != 22 ] || host="${host%%:*}"
    for h in MD5 SHA256; do
        ssh-keygen -E "$h" -f "$DIR/../ssh_known_hosts" -lF "${host#*@}"
    done | sed -nr 's/^[^ #]+\s+//p' | sed -r 's/^(\S+)\s+(MD5|SHA256):/\1 \2 /' |
    while read t h fpr; do
        echo -n "$indent$t"
        for i in $(seq 1 $((7 - ${#h}))); do echo -n ' '; done
        echo "$h:$fpr"
    done
}

allfpr() {
    local typ="$1"
    [ "$typ" = mdwn ] && indent='        ' || indent='    '
	cat <<- EOF
	 * IMAP server
		$(x509fpr 'imap.fripost.org:993 (IMAP over SSL), sieve.fripost.org:4190 (ManageSieve, STARTTLS)')

	 * SMTP servers (STARTTLS)
		$(x509fpr 'smtp.fripost.org:587 (Mail Submission Agent)')
	
		$(x509fpr 'mx1.fripost.org:25 (1st Mail eXchange)')
	
		$(x509fpr 'mx2.fripost.org:25 (2nd Mail eXchange)')

	 * Web servers
		$(x509fpr 'fripost.org:443 (website), wiki.fripost.org:443 (wiki)')
	
		$(x509fpr 'mail.fripost.org:443 (webmail)')
	
		$(x509fpr 'lists.fripost.org:443 (list manager)')
	
		$(x509fpr 'git.fripost.org:443 (git server and its web interface)')

	 * SSH server
		$(sshfpr 'gitolite@git.fripost.org:22')
	EOF
}


[ $# -eq 1 ] || usage

asc="$1"
asc2=$(mktemp --tmpdir)
src=$(mktemp --tmpdir)
src2=$(mktemp --tmpdir)
mdwn="${asc%.asc}.mdwn"
mdwn2=$(mktemp --tmpdir)
DIR="$(dirname "$0")/public"
VCS_BROWSER='https://git.fripost.org/fripost-ansible'
trap 'rm -f "$src" "$src2" "$asc2" "$mdwn2"' EXIT

if [ -s "$asc" ]; then
    "$GPG" $GPG_OPTS --logger-file=/dev/null --output="$src" -- "$asc"
fi


# Generate ASCII file to be clearsigned
cat >"$src2" << EOF
The following is an up-to date list of SHA-1 and SHA-256 fingerprints of all
X.509 certificates Fripost uses on its publicly available services.  Please
consider any mismatch as a man-in-the-middle attack, and let us know
immediately! -- admin@fripost.org


All our X.509 certificates are available in PEM format under

    $VCS_BROWSER/tree/certs/public ,

Git repository from which this fingerprint list was generated, at commit ID
$(git --no-pager --git-dir="$DIR/../../.git" --work-tree="$DIR" log -1 --pretty=format:'%h from %aD' -- "$DIR").


EOF
allfpr asc >>"$src2"


# Generate markdown file
cat >"$mdwn2" << EOF
# Certificates at Fripost

The following is an up-to date list of SHA-1 and SHA-256 fingerprints of all
X.509 certificates Fripost uses on its publicly available services.  Please
consider any mismatch as a man-in-the-middle attack, and let us know
immediately!  (See also the [[signed version of this page|certs.asc]].)
-- [[admin@fripost.org|mailto:admin@fripost.org]]


All our X.509 certificates are available in PEM format under our
[[Git repository|$VCS_BROWSER/tree/certs/public]],
from which this fingerprint list was [[generated|$VCS_BROWSER/tree/certs/gencerts.sh]], at
$(git --no-pager --git-dir="$DIR/../../.git" --work-tree="$DIR" log -1 --pretty=format:"[[Commit ID %h from %aD|$VCS_BROWSER/tree/certs/public?id=%H]]" -- "$DIR").


EOF
allfpr mdwn >>"$mdwn2"
tee -a "$src2" >> "$mdwn2" << EOF


If your SSL/TLS-capable client is able to validate the public key
fingerprint of the remote peer certificate, then you should probably use
this (the above values prefixed with "PKey") instead of the fingerprint
of the certificate instead (the above values prefixed with "X.509"),
since the former typically doesn't change upon certificate renewal.
EOF
echo >>"$src2"


if diff -u --label "a/${asc%.asc}" --label "b/${asc%.asc}" -- "$src" "$src2" &&
   diff -q -- "$mdwn" "$mdwn2" >/dev/null; then
    echo 'The fingerprint list is up to date.'
else
    "$GPG" $GPG_OPTS --output="$asc2" --clearsign -- "$src2"
    cp -f "$asc2" "$asc"
    cp -f "$mdwn2" "$mdwn"
    echo ================================ 
    echo "The fingerprint lists ($asc and $mdwn) have been updated!"
    echo '/!\ You should now push the changes to the wiki. /!\'
fi