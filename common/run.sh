#!/bin/bash
target="/provisioning"
outlog="$1"; shift
cd $target || { echo "ERROR: "$target" directory not found!"; exit 1; }
exec ./configure.sh "$@" > "$outlog" 2>&1
