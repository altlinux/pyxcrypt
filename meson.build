project('pyxcrypt', 'c')
lxcrypt = dependency('libxcrypt')

py = import('python').find_installation('python3', pure: false)

py.extension_module('pyxcrypt',
'src/pyxcrypt/pyxcrypt.c',
dependencies: lxcrypt,
install: true,
subdir: 'pyxcrypt'
)

py.install_sources(
  'src/pyxcrypt/__init__.py',
  subdir: 'pyxcrypt'
)

install_data(
  'README.md',
  install_dir: py.get_install_dir() / 'pyxcrypt'
)

python_paths = [join_paths(meson.current_build_dir(), '../src/')]
run_tests = find_program('tests/run_tests.sh')
test('unit-tests',
  run_tests,
  args: ['../tests'],
)
