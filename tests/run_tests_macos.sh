#!/bin/sh

mkdir -p /tmp/test_env
DESTDIR=/tmp/test_env meson install
PYTHONPATH=$(find /tmp/test_env -name pyxcrypt -exec dirname {} +) python3 -P -m unittest discover -s "$1" -v
