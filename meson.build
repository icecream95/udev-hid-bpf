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

filters = get_option('bpf-filter')
have_filters = filters != []

subset = get_option('bpfs')
build_testing = 'testing' in subset or have_filters
build_stable = 'stable' in subset or have_filters
build_userhacks = 'userhacks' in subset or have_filters

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

# For cargo we need to mirror much of the source tree
fs = import('fs')
bpf_sources = files()
bpf_copied_sources = files()
bpf_o_files = []
subdir('src')

bpf_output_files = []
foreach f : bpf_sources
    bpf_output_files = fs.replace_suffix(f, '.o')
endforeach

# Now the cargo invocation
cargo_env = {
    'MESON_BUILD': '1',
    'CARGO_HOME': meson.project_build_root() / 'cargo-home',
    'CARGO_TARGET_DIR': meson.project_build_root(),
    'BPF_SOURCE_ROOT': meson.project_build_root(),
    'OUT_DIR': meson.project_build_root(),
    'EXTRA_INCLUDE': meson.project_source_root() / 'src' / 'bpf',
}

cargo_env_list  = []
foreach k,v : cargo_env
    cargo_env_list += '@0@=@1@'.format(k, v)
endforeach

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
  depends: bpf_copied_sources,
  command: [
    'env',
    cargo_env_list,
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', 'src' / rust_target / meson.project_name(), '@OUTPUT@',
  ]
)

meson.add_devenv(cargo_env)

subdir('bpf')

udev_config = configuration_data()
# See make_release.sh - if set we leave a placeholder
# that we can use in install_release.sh
if get_option('placeholder-udev-rules-file')
    udev_config.set('BINDIR', '@@BINDIR@@')
else
    udev_config.set('BINDIR', bindir)
endif
configure_file(input: '99-hid-bpf.rules.in',
               output: '@BASENAME@',
               configuration: udev_config,
               install: true,
               install_dir: udevdir / 'rules.d')

json_data = custom_target(
    'extract json data',
    depends: cargo_build,
    output: 'bpf.json',
    capture: true,
    command: [
        cargo_build,
        'inspect',
        bpf_o_files
    ]
)

hwdb = custom_target(
    'hwdb files',
    depends: json_data,
    build_by_default: true,
    output: '99-hid-bpf.hwdb',
    input: json_data,
    command: [
        find_program('tools/generate-hwdb.py'),
    ],
    feed: true,
    capture: true,
    install: true,
    install_dir: udevdir / 'hwdb.d',
)
