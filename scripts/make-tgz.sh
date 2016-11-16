#!/bin/bash

set -eux

prefix_version="2.0"
patch_version="$(git rev-list --count HEAD 2>/dev/null)"

[[ "$patch_version" = "" ]] && patch_version="0"

out_epoch=$(date -u '+%s')
out_seqid=$(printf "%x" "$out_epoch")

version=${prefix_version}.${patch_version}-${out_seqid}

out_base="output"
out_data="archive"

out_path="${out_base}/${out_data}"
out_name="provisioning-${version}"
out_file="${out_base}/${out_name}.tgz"

excludes()
{
    local prog="$1"; shift
    $prog --exclude '.git*' --exclude '*.log' --exclude '*.pyc' --exclude '*.pyo' --exclude "${out_base}" "$@"
}

(cd $out_base && rm -rf $out_data)

mkdir -p $out_path

excludes rsync -axv . $out_path

sed -i -e "s#^\(__version__ =[ \t]\+\).\+#\1'${version}'#" "${out_path}/common/provision.py"

tar --owner=root --group=root --transform "s#^${out_path}\(.*\)\$#${out_name}/\1#" -zcf $out_file $out_path

(cd $out_base && rm -rf $out_data)
