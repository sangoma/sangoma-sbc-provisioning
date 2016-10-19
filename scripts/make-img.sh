#!/bin/bash

[[ $(whoami) != "root" ]] && \
{
    echo "need to be root"
    exit 1
}

major_version="1"
minor_version="$(git rev-list --count HEAD 2>/dev/null)"

[[ "$minor_version" = "" ]] && minor_version="0"

set -eux

out_tsmp=$(date -u '+%s')
out_numb=$(printf "%x" "$out_tsmp")

out_base="output/"
out_path="${out_base}/mnt"
out_file="${out_base}/provisioning-${major_version}.${minor_version}-${out_numb}.img"

excludes()
{
    local prog="$1"; shift
    $prog --exclude '.git*' --exclude '*.log' --exclude "${out_base}*" "$@"
}

kbsize="$(excludes du -s . | cut -f1)"

[[ "$kbsize" ]] || exit 1

kbsize="$[$kbsize+50000]"

echo "creating partition with ${kbsize} kilobytes"

truncate -s "${kbsize}K" $out_file

ls -lah $out_file

mke2fs -m0 $out_file

ls -lah $out_file

umount $out_path || true

mkdir -p $out_path

mount -o loop $out_file $out_path

excludes rsync -axv . "$out_path"

umount $out_path

gzip -1 $out_file
