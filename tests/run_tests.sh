#!/bin/sh

mkdir -p /tmp/test_env
meson compile
DESTDIR=/tmp/test_env meson install
PYTHONPATH=$(find /tmp/test_env -name pyxcrypt -printf %h) python3 -P -m unittest discover -s "$1" -v
