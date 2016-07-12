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
    local msg="$1" host pub h spki
    host="${msg%%,*}"; host="${host%% *}"; host="${host#\`}"
    pub="$DIR/${host%%:*}.pub"
    spki=$(openssl pkey -pubin -outform DER <"$pub" | openssl dgst -sha256 | sed -nr 's/^[^=]+=\s*//p')
    [ "$typ" = mdwn ] && printf '\n    [%s](https://crt.sh/?spkisha256=%s&iCAID=16418&exclude=expired)\n\n' "$msg" "$spki" \
                      || printf '    %s\n    X.509: https://crt.sh/?spkisha256=%s&iCAID=16418&exclude=expired\n    SPKI:\n' \
                                "$(printf '%s' "$msg" | tr -d '`' )" "$spki"
    for h in sha1 sha256; do
        x509fpr2 "$h" "$pub"
    done

    local backup=$(find "$DIR" -maxdepth 1 -type f -name "${host%%:*}.pub.back*")
    if [ "$backup" -a "$typ" != mdwn ]; then
        echo "    Backup SPKI:"
        for pub in $backup; do
            x509fpr2 "$h" "$pub"
        done
    fi
}
x509fpr2() {
    local h="$1" pub="$2" str dgst

    [ "$typ" = mdwn ] && str= || str='  '
    str="$str$(printf '%-6s' "$h" | tr '[a-z]' '[A-Z]')"
    dgst="$(openssl pkey -pubin -outform DER <"$pub" | openssl dgst -"$h" -binary | base64)"
    hd=$(printf '%s' "$dgst" | base64 -d | xxd -c256 -p | tr '[a-f]' '[A-F]' | sed -e 's/../&:/g' -e 's/:$//')
    if [ $((${#indent} + ${#str} + 1 + ${#hd})) -le 72 ]; then
        printf '%s %s\n' "$indent$str" "$hd"
    else
        printf '%s %s\n' "$indent$str" "$dgst"
    fi
}

sshfpr() {
    local msg="$1" host h fpr str
    host="${msg%%,*}"; host="${host%% *}"; host="${host#*@}"; host="${host#\`}"; host="${host%\`}"
    [ "$typ" = mdwn ] && { echo; echo "    $msg"; echo; } || { echo "    $msg" | tr -d '`'; }
    [ "${host#*:}" != 22 ] || host="${host%%:*}"
    [ "$typ" = mdwn ] && str= || str='  '
    for h in MD5 SHA256; do
        ssh-keygen -E "$h" -f "$DIR/../ssh_known_hosts" -lF "${host#*@}"
    done | sed -nr 's/^[^ #]+\s+//p' | sed -r 's/^\S+\s+([^:]+):/\1 /' |
    while read h fpr; do
        str2="$str$(printf '%-6s' "$h" | tr '[a-z]' '[A-Z]')"
        printf '%s %s\n' "$indent$str2" "$fpr"
    done
}

allfpr() {
    local typ="$1"
    [ "$typ" = mdwn ] && indent='        ' || indent='    '
	cat <<- EOF
	 * IMAP server
		$(x509fpr '`imap.fripost.org:993` (IMAP over SSL), `sieve.fripost.org:4190` (ManageSieve, `STARTTLS`)')

	 * SMTP servers
		$(x509fpr '`smtp.fripost.org:587` (Mail Submission Agent, `STARTTLS`)')
	
		$(x509fpr '`mx1.fripost.org:25` (1st Mail eXchange, `STARTTLS`)')
	
		$(x509fpr '`mx2.fripost.org:25` (2nd Mail eXchange, `STARTTLS`)')

	 * Web servers
		$(x509fpr '`fripost.org:443`, `www.fripost.org:443` (website), `wiki.fripost.org:443` (wiki)')
	
		$(x509fpr '`mail.fripost.org:443`, `webmail.fripost.org:443` (webmail)')
	
		$(x509fpr '`lists.fripost.org:443` (list manager)')
	
		$(x509fpr '`git.fripost.org:443` (git server and its web interface)')

	 * SSH server
		$(sshfpr '`gitolite@git.fripost.org:22`')
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
The following is an up-to date list of SHA-1 and SHA-256 fingerprints of
all SPKI (Subject Public Key Info) of each X.509 certificate Fripost
uses on its publicly available services.  Please consider any mismatch
as a man-in-the-middle attack, and let us know immediately! --
admin@fripost.org


These certificates are all issued by the Let's Encrypt Certificate
Authority, and are submitted to Certificate Transparency logs. You can
view all issued Let's Encrypt certificates at crt.sh:

    https://crt.sh/?Identity=%25fripost.org&iCAID=16418

The SPKI of our X.509 certificates are also available in PEM format at:

    $VCS_BROWSER/tree/certs/public ,

Git repository from which this fingerprint list was generated, at commit ID
$(git --no-pager --git-dir="$DIR/../../.git" --work-tree="$DIR" log -1 --pretty=format:'%h from %aD' -- "$DIR").


EOF
allfpr asc >>"$src2"


# Generate markdown file
cat >"$mdwn2" << EOF
# Certificates at Fripost

The following is an up-to date list of SHA-1 and SHA-256 fingerprints of
all SPKI (Subject Public Key Info) of each X.509 certificate Fripost
uses on its publicly available services.  Please consider any mismatch
as a man-in-the-middle attack, and let us know immediately!  (See also
the [signed version of this page](/certs.asc).)
-- [the admin team](mailto:admin@fripost.org)


These certificates are all issued by the [Let's Encrypt Certificate
Authority](https://letsencrypt.org), and are submitted to [Certificate
Transparency logs](https://www.certificate-transparency.org).
You can view all issued Let's Encrypt certificates at
[crt.sh](https://crt.sh/?Identity=%25fripost.org&iCAID=16418).
The SPKI of our X.509 certificates are also available in PEM format
under our [Git repository]($VCS_BROWSER/tree/certs/public),
from which this fingerprint list was [generated]($VCS_BROWSER/tree/certs/gencerts.sh), at
$(git --no-pager --git-dir="$DIR/../../.git" --work-tree="$DIR" log -1 --pretty=format:"[Commit ID %h from %aD]($VCS_BROWSER/tree/certs/public?id=%H)" -- "$DIR").


EOF
allfpr mdwn >>"$mdwn2"
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
