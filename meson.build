project('udev-hid-bpf', 'rust')

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
bpfdir = prefix / 'lib' / 'firmware' / 'hid' / 'bpf'

pkgconfig = import('pkgconfig')
udevdir = get_option('udevdir')
if udevdir == ''
    udev = dependency('udev', required: false)
    if udev.found()
        udevdir = udev.get_variable('udevdir')
    else
        udevdir = prefix / 'lib' / 'udev'
    endif
endif

subset = get_option('bpfs')
build_testing = 'testing' in subset
build_stable = 'stable' in subset
build_userhacks = 'userhacks' in subset

cargo = find_program('cargo', required: true)

cargo_options = [ '--manifest-path', meson.project_source_root() / 'Cargo.toml' ]
cargo_options += [ '--target-dir', meson.project_build_root() / 'src' ]

if get_option('buildtype') == 'release'
  cargo_options += [ '--release' ]
  rust_target = 'release'
  message('Building in release mode')
else
  rust_target = 'debug'
  message('Building in debug mode')
endif

features = ''
if build_testing
    features += 'testing,'
endif
if build_stable
    features += 'stable,'
endif
if build_userhacks
    features += 'userhacks,'
endif
if features != ''
    cargo_options += ['--features=@0@'.format(features)]
endif

# For cargo we need to mirror much of the source tree
fs = import('fs')
bpf_sources = files()
bpf_copied_sources = files()
subdir('src')

bpf_output_files = []
foreach f : bpf_sources
    bpf_output_files = fs.replace_suffix(f, '.o')
endforeach

# Now the cargo invocation
cargo_env = [
    'CARGO_HOME=@0@/cargo-home'.format(meson.project_build_root()),
    'CARGO_TARGET_DIR=@0@'.format(meson.project_build_root()),
    'BPF_SOURCE_ROOT=@0@'.format(meson.project_build_root()),
    'OUT_DIR=@0@'.format(meson.project_build_root()),
    'EXTRA_INCLUDE=@0@'.format(meson.project_source_root() / 'src' / 'bpf'),
]

# Note: with the env set up the cp command only copies the
# udev-hid-bpf binary, the bpf files are built in-place (i.e. builddir/bpf)
# because of the crazy build.rs script we need.
cargo_build = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: meson.project_name(),
  console: true,
  install: true,
  install_dir: bindir,
  # depend_files: bpf_copied_sources,
  depends: bpf_copied_sources,
  command: [
    'env',
    cargo_env,
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', 'src' / rust_target / meson.project_name(), '@OUTPUT@',
  ]
)

subdir('bpf')

udev_config = configuration_data()
udev_config.set('BINDIR', bindir)
configure_file(input: '99-hid-bpf.rules.in',
               output: '@BASENAME@',
               configuration: udev_config,
               install: true,
               install_dir: udevdir / 'rules.d')
