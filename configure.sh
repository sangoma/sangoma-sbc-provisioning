#!/bin/bash
[[ -d common ]] || { echo 'ERROR: "common" directory not found!'; exit 1; }
exec env PYTHONPATH="./common:$PYTHONPATH" /usr/bin/python2.7 common/provision.py "$@"
