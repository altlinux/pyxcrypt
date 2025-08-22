project('pyxcrypt', 'c')
lxcrypt = dependency('libxcrypt')

py = import('python').find_installation('python3', pure: false)

py.extension_module('pyxcrypt',
'src/pyxcrypt/pyxcrypt.c',
dependencies: lxcrypt,
install: true,
subdir: 'pyxcrypt'
)

install_data(
  'src/pyxcrypt/__init__.py',
  install_dir: py.get_install_dir() / 'pyxcrypt'
)

install_data(
  'README.md',
  install_dir: py.get_install_dir() / 'pyxcrypt'
)
