#!/bin/bash
exec env PYTHONPATH=".:$PYTHONPATH" /usr/bin/python2.7 provision.py "$@"
