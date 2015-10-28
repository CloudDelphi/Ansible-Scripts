#!/bin/sh

set -ue
PATH=/usr/bin:/bin

privkey="$1"
bits="${2:-2048}"
rand=

install --mode=0600 /dev/null "$privkey"
openssl dhparam -rand "${rand:-/dev/urandom}" "$bits" >"$privkey"
