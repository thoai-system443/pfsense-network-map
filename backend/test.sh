#!/bin/sh
set -e

# Mount the working tree over the image's copy so a test run always sees current
# source. Without this every red/green cycle would need a rebuild.
docker compose run --rm --no-deps \
    -v "$PWD/app:/app/app" \
    -v "$PWD/tests:/app/tests" \
    api python -m pytest "$@"
