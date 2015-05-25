#!/bin/sh

set -ue
PATH=/usr/bin:/bin

privkey="$1"
bits="${2:-2048}"
rand=

mv -f "$(mktemp)" "$privkey"
chmod og-rwx "$privkey"

openssl dhparam -rand "${rand:-/dev/urandom}" "$bits" >"$privkey"
