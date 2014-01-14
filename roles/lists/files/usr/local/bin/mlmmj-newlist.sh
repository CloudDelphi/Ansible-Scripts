#!/bin/sh

# Add new lists (with a common options) to be managed by mlmmj.
# Incoming e-mails need to be handed over (piped) to mlmmj-receive(1) by
# the MTA, see http://mlmmj.org/docs/readme-postfix/ to configure the
# MTA.
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

fail () {
    echo Error: "$@" >&2
    exit 1
}

spool=/var/spool/mlmmj  # mlmmj's how private directory
lib=/var/lib/mlmmj      # shared by mlmmj and (partially) by the web server
webhost=https://lists.fripost.org
umask 0022

[ $# -ge 2 -a $# -le 3 ] || { echo "Usage: $0 list owner [language]"; exit; }
list="$1"
owner="$2"
lang="${3:-en}"

localpart="${list%@*}"
domainpart="${list##*@}"
[ "$localpart" = "$list" ] && [ "$domainpart" = "$list" ] \
&& fail "$list is not fully-qualified"

[ -d "$spool/$domainpart/$localpart" -o -d "$lib/$domainpart/$localpart" ] \
&& fail "$list exists"

ls -1 /usr/share/mlmmj/text.skel | grep -qFx "$lang" \
|| fail "Available languages: $(echo $(ls /usr/share/mlmmj/text.skel))"

case "$webhost" in
    *"/$domainpart") listurl="$webhost/$localpart/";;
    *)               listurl="$webhost/$domainpart/$localpart/";;
esac

mkdir -p -m0700 "$spool/$domainpart/$localpart"
mkdir -p -m0750   "$lib/$domainpart/$localpart"


# The web server has read-only access to subscribers.
for dir in subscribers.d digesters.d nomailsubs.d; do
    mkdir -m0750 "$lib/$domainpart/$localpart/$dir"
    ln -s        "$lib/$domainpart/$localpart/$dir" \
                 "$spool/$domainpart/$localpart/$dir"
done

# The web server can update the list configuration.
mkdir -m2770 "$lib/$domainpart/$localpart/control"
ln -s        "$lib/$domainpart/$localpart/control" \
             "$spool/$domainpart/$localpart/control"

# Internal directories.
for dir in incoming queue queue/discarded \
           subconf unsubconf bounce moderation requeue; do
    mkdir -m0700 "$spool/$domainpart/$localpart/$dir"
done

# Link to templates.
ln -s /usr/share/mlmmj/text.skel/$lang "$spool/$domainpart/$localpart/text"

# Archives are private, but web archives are public.
mkdir -m0700 "$lib/$domainpart/$localpart/archive"
mkdir -m0750 "$lib/$domainpart/$localpart/webarchive"
ln -s "$lib/$domainpart/$localpart/archive" \
      "$spool/$domainpart/$localpart/archive"
ln -s "$lib/$domainpart/$localpart/webarchive" \
      "$spool/$domainpart/$localpart/webarchive"

# Default configuration, non-writable from the web.
echo "$list"   > "$lib/$domainpart/$localpart/control/listaddress"
echo "$owner"  > "$lib/$domainpart/$localpart/control/owner"
# XXX: these tunables are ignored, see http://mlmmj.org/bugs/bug.php?id=51
#echo 127.0.0.1 > "$lib/$domainpart/$localpart/control/relayhost"
#echo 16132     > "$lib/$domainpart/$localpart/control/smtpport"
echo month     > "$lib/$domainpart/$localpart/control/archiverotate"

# RFC 2369
cat > "$lib/$domainpart/$localpart/control/customheaders" <<- EOF
	Errors-to: $localpart+owner@$domainpart
    Precedence: list
	List-Id: <$localpart.$domainpart>
	List-URL: <$listurl>
	List-Post: <mailto:$list>
	List-Help: <mailto:$localpart+help@$domainpart>,
        <$listurl/>
	List-Subscribe: <$localpart+subscribe@$domainpart>,
        <$listurl/>
	List-Unsubscribe: <mailto:$localpart+unsubscribe@$domainpart>,
        <$listurl/>
    List-Owner: <mailto:$localpart+owner@$domainpart>
	List-Archives: <$listurl/archives/>
	Reply-To: $list
	X-MailingList: $list
	X-Loop: $list
EOF
cat > "$lib/$domainpart/$localpart/control/delheaders" <<- EOF
	Return-Receipt-To:
	Disposition-Notification-To:
	X-Confirm-Reading-To:
	X-Pmrqc:
EOF

# Some useful default, that the user is free to change via the web
# interface.
cat > "$lib/$domainpart/$localpart/control/footer" <<- EOF
	_______________________________________________
	$localpart mailing list
	$localpart@$domainpart
	$listurl
EOF
echo "[$localpart]" > "$lib/$domainpart/$localpart/control/prefix"
touch "$lib/$domainpart/$localpart/control/subonlypost" \
      "$lib/$domainpart/$localpart/control/subonlyget"

for control in customheaders footer prefix subonlypost subonlyget; do
    chmod 0664 "$lib/$domainpart/$localpart/control/$control"
done

# TODO: welcome mail
