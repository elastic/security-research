#!/bin/bash
set -e

# Load runtime
. /runtime/bin/activate

if [ $# -eq 0 ]; then
    # Default case of no args
    ls /runtime/bin/bpfdoor-extractor
    set -- /runtime/bin/bpfdoor-extractor
elif [ "${1:0:1}" = '-' ]; then
    # If the user is trying to run the script directly with some arguments,
    # then pass them along.
    set -- /runtime/bin/bpfdoor-extractor "$@"
elif [ $# -gt 0 ]; then
    # Run whatever command the user wanted
    exec "$@"
fi

exec "$@"
