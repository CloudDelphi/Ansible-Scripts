#!/bin/sh

# Convert a list archive into HTML.
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

[ $# -eq 1 ] || { echo "Usage: $0 listdir"; exit; }
listdir="${1%/}"
[ -d "$listdir" ] || fail "No such directory: $listdir"

localpart="${listdir##*/}"
domainpart="${listdir%/$localpart}"
domainpart="${domainpart##*/}"

# Determine the rotation period
rotation=
[ -s "$listdir/control/archiverotate" ] && read rotation <"$listdir/control/archiverotate"

# Subdir format (/!\ shouldn't be empty, and shouldn't contain spaces!),
# and archive date format.
case "${rotation:-month}" in
    '')    subdirf='/'         listpage='./';        archivef=;;
    year)  subdirf="%Y";       listpage='../';       archivef="for %Y";;
    month) subdirf="%Y/%m";    listpage='../../';    archivef="for %B %Y";;
    day)   subdirf="%Y/%m/%d"; listpage='../../../'; archivef="for %a, %d %b %Y";;
    *)     fail "$rotation: unknown rotation period"
esac

# Look up for the send date in an email. Fall back to the creation date
# if not found.
printDate () {
    local filename date
    while read filename; do
        if ! [ "$rotation" ]; then
            # don't bother looking for a date
            date=0
        else
            # stop as soon as the header is over
            date=$(sed -nr '/^Date:\s*(\S.*)$/I {s//\1/p;q}; /^([^[:cntrl:][:space:]]+:|\s)/ !q' \
                           "$filename")
            [ "$date" ] || date=@$(stat -c '%Y' "$filename")
        fi
        echo $(date -d "$date" +"%s $subdirf") "$filename"
    done
}

# Process a (single) subdirectory
process () {
    local list="$1" subdir="$2" date="$3"
    [ -s "$list" ] || return 0

    [ -d "$listdir/webarchive/$subdir" ] || mkdir -p "$listdir/webarchive/$subdir"
    # TODO: add a line to the index file
    xargs -a"$list" mhonarc -definevar ListName="'$localpart'" \
                            -definevar ListPage="'${listpage}index.html'" \
                            -definevar DirDate="'$date'" \
                            -rcfile /etc/mhonarc.rc \
                            -add \
                            -quiet \
                            -outdir "$listdir/webarchive/$subdir" \
    || exit 1
    # empty the list
    echo -n >"$list"
}

# Process all found emails
processM () {
    local cursubdir= date=
    local timestamp subdir filename

    while read timestamp subdir filename; do
        if [ "$cursubdir" != "$subdir" ]; then
            process "$list" "$cursubdir" "$date"
            cursubdir="$subdir"
            date="$(date -d "@$timestamp" +"$archivef")"
        fi
        echo "$filename" >>"$list"
    done
    process "$list" "$cursubdir" "$date"
}

# The span of emails we'll touch during the current instance
now=$(date +'%s')
list=$(mktemp) || exit 1
trap 'rm -f "$list"' EXIT

from=0
if [ -s "$listdir/.webarchive.date" ]; then
    read from <"$listdir/.webarchive.date"
    from=$(( $from - 30 )) # remove 30s to fight race conditions
fi

find "$listdir/archive/" -type f -a -newermt @"$from" | printDate | sort -n -k1,1 | processM
echo "$now" > "$listdir/.webarchive.date"
