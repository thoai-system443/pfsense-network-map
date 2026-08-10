#!/bin/sh
set -e

: "${API_URL:=http://localhost:8010}"

# Escape backslash then quote so an API_URL containing either cannot break out
# of the JavaScript string literal.
escaped=$(printf '%s' "$API_URL" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
printf 'window.__CONFIG__ = { API_URL: "%s" };\n' "$escaped" \
    > /usr/share/nginx/html/config.js

exec nginx -g 'daemon off;'
