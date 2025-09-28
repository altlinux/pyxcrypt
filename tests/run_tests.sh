#!/bin/sh

mkdir -p /tmp/test_env
meson compile
DESTDIR=/tmp/test_env meson install
PYTHONPATH=/tmp/test_env/usr/local/lib/python3/site-packages:/tmp/test_env/usr/local/lib64/python3/site-packages python3 -P -m unittest discover -s "$1" -v
