#!/bin/sh

set -ue
PATH=/usr/bin:/bin

out="$1"
bits="${2:-2048}"

install --mode=0644 /dev/null "$out"
openssl dhparam -rand /dev/urandom "$bits" >"$out"
