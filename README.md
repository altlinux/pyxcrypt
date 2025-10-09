# pyxcrypt
Simple python3 bindings to libxrcypt[1].

## Build and Install
You can build and install pyxcrypt as a wheel package using pip[2] or
by using meson. For both cases you will need theese build requirements:
1. C-compiler (gcc, for example)
2. libxcrypt
3. Python3 standart library

If you build pyxcrypt using meson you will also need meson[3]. And if you want
to use pip, you will need pip[2]:).

**ATTENTION** MacOS users have to specify path to libxcrypt since they install
it using brew:
```
export PKG_CONFIG_PATH=/opt/homebrew/opt/libxcrypt/lib/pkgconfig
```

### Build and install using pip
The simpliest way is to install pyxcrypt from pypi[4]:
```
python3 -m venv /tmp/env
source /tmp/env/bin/activate
pip3 install pyxcrypt
```

But if you want to test development version of pyxcrypt, you can build it
from source using pip:
```
python3 -m venv /tmp/env
source /tmp/env/bin/activate
git -C clone /tmp https://github.com/altlinux/pyxcrypt.git
pip install /tmp/pyxcrypt
```

### Build and install using meson
```
git -C /tmp clone https://github.com/altlinux/pyxcrypt.git
cd /tmp/pyxcrypt && meson BUILD_DIR
meson compile -C BUILD_DIR
```

After these steps you can just install it using:
```
meson install -C BUILD_DIR
```
But it is better to specify **DESTDIR** and than set **PYTHONPATH** so you
can install it as user.

### Running tests
Also you can run tests by calling meson:
```
meson BUILD_DIR
meson test -C BUILD_DIR
```

Or after install it using pip:
```
python3 -m unittest discover -s tests -v
```

## Docs
Since **pyxcrypt** just uses libxcrypt[1] API all main pyxcrypt functions are
equal to libxcrypt. For API doc import **pyxcrypt** from python3 and run
**help(pyxcrypt)** or visit this link[5]


## Links
- [1] - https://github.com/besser82/libxcrypt
- [2] - https://pypi.org/project/pip/
- [3] - https://mesonbuild.com/
- [4] - https://pypi.org/
- [5] - https://altlinux.github.io/pyxcrypt
