#!/bin/bash

prefix_version="2.0"
patch_version="$(git rev-list --count HEAD 2>/dev/null)"

[[ "$patch_version" = "" ]] && patch_version="0"

set -eux

out_tsmp=$(date -u '+%s')
out_numb=$(printf "%x" "$out_tsmp")

out_base="output"
out_name="provisioning-${prefix_version}.${patch_version}-${out_numb}"
out_file="${out_base}/${out_name}.tgz"

excludes()
{
    local prog="$1"; shift
    $prog --exclude '.git*' --exclude '*.log' --exclude "${out_base}" "$@"
}

excludes tar --owner=root --group=root --transform "s#^[.]/\(.\+\)\$#${out_name}/\1#" -zcf $out_file .
