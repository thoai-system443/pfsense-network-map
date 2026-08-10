#!/bin/sh
set -e

if [ -z "$DOCS_USER" ] || [ -z "$DOCS_PASSWORD" ]; then
    echo "FATAL: DOCS_USER and DOCS_PASSWORD must be set" >&2
    exit 1
fi

# Check the hash explicitly. A command substitution that fails inside printf
# arguments does not trip set -e, which would leave a truncated .htpasswd behind
# and reject every request with a silent 401.
if ! hash=$(openssl passwd -apr1 "$DOCS_PASSWORD"); then
    echo "FATAL: could not hash DOCS_PASSWORD" >&2
    exit 1
fi

if [ -z "$hash" ]; then
    echo "FATAL: password hash came back empty" >&2
    exit 1
fi

printf '%s:%s\n' "$DOCS_USER" "$hash" > /etc/nginx/.htpasswd
exec nginx -g 'daemon off;'
