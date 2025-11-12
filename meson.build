project('pyxcrypt', 'c', meson_version: '>= 1.3.0')

compiler = meson.get_compiler('c')
conf_data = configuration_data()
lxcrypt = dependency('libxcrypt')

if compiler.has_function('SecureZeroMemory', prefix : '#include <Windows.h>')
  conf_data.set('PYXCRYPT_HAVE_SECUREZEROMEMORY', true)
else
  if compiler.has_function('memset_explicit', prefix : '#include <string.h>')
    conf_data.set('PYXCRYPT_HAVE_MEMSET_EXPLICIT', true)
  else
    if compiler.has_function('explicit_bzero', prefix : '#include <string.h>')
      conf_data.set('PYXCRYPT_HAVE_EXPLICIT_BZERO', true)
    else
      conf_data.set('PYXCRYPT_USE_MEMERASE_IMPL', true)
    endif
  endif
endif

pyxcrypt_src = [
  'src/pyxcrypt/pyxcrypt.c',
  'src/pyxcrypt/pyxcrypt-memerase.c'
]

py = import('python').find_installation('python3', pure: false)

py.extension_module(
  'pyxcrypt',
  pyxcrypt_src,
  dependencies: lxcrypt,
  install: true,
  subdir: 'pyxcrypt',
  limited_api: '3.2'
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
if host_machine.system() == 'darwin'
  run_tests = find_program('tests/run_tests_macos.sh')
else
  run_tests = find_program('tests/run_tests.sh')
endif
test('unit-tests',
  run_tests,
  args: ['../tests'],
)

configure_file(
  input : 'src/pyxcrypt/pyxcrypt-config.h.in',
  output : 'pyxcrypt-config.h',
  configuration : conf_data
)
