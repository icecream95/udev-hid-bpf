project('udev-hid-bpf', 'rust', 'c',
        version: '2.1.0-20240704', # Update Cargo.toml too!
        meson_version: '>= 1.0.0')

cc = meson.get_compiler('c')

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
bpfdir = prefix / 'lib' / 'firmware' / 'hid' / 'bpf'
man1dir  = prefix / get_option('mandir') / 'man1'

lookup_bpfdirs = []
dirs = get_option('bpfdirs')
if dirs.length() == 0
    dirs = ['PREFIXED_BPFDIR']
endif
foreach d: dirs
    d = d.replace('PREFIXED_BPFDIR', bpfdir)
    if not lookup_bpfdirs.contains(d)
        lookup_bpfdirs += [d]
    endif
endforeach

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

cargo = find_program('cargo', required: true)

use_bpf_tracing = get_option('bpf-tracing')

cargo_options = [
    '--manifest-path', meson.project_source_root() / 'Cargo.toml',
    '--target-dir', meson.project_build_root(),
]

if get_option('buildtype') in ['debug', 'debugoptimized']
  cargo_options += [ '--all-targets' ]
  rust_target = 'debug'
  message('Building in debug mode')
else
  cargo_options += [ '--release' ]
  rust_target = 'release'
  message('Building in release mode')
endif

subdir('src')

# Now the cargo invocation
cargo_env = {
    'MESON_BUILD': '1',
    'MESON_BINDIR': bindir,
    'CARGO_HOME': meson.project_build_root() / 'cargo-home',
    'BPF_SOURCE_ROOT': meson.project_source_root(),
    'BPF_INSTALL_DIR': bpfdir,
    'BPF_LOOKUP_DIRS': lookup_bpfdirs,
}

cargo_files = files(
    'Cargo.toml',
    'build.rs',
    'src/bpf/attach.bpf.c',
    'src/bpf.rs',
    'src/hid_bpf_wrapper.h',
    'src/hidudev.rs',
    'src/main.rs',
    'src/meson.build',
    'src/modalias.rs',
)

# Note: with the env set up the cp command only copies the
# udev-hid-bpf binary, the bpf files are built in-place (i.e. builddir/bpf)
# because of the crazy build.rs script we need.
cargo_build = custom_target(
  'cargo-build',
  build_by_default: true,
  output: meson.project_name(),
  console: true,
  install: true,
  install_dir: bindir,
  depend_files: cargo_files,
  env: cargo_env,
  command: [
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', rust_target / meson.project_name(), '@OUTPUT@',
  ]
)

test('cargo test',
    cargo,
    args: ['test'],
    env: cargo_env,
    timeout: 120,
)

meson.add_devenv(cargo_env)

udev_config = configuration_data()
# See make_release.sh - if set we leave a placeholder
# that we can use in install_release.sh
if get_option('placeholder-udev-rules-file')
    udev_config.set('BINDIR', '@@BINDIR@@')
else
    udev_config.set('BINDIR', bindir)
endif
configure_file(input: '81-hid-bpf.rules.in',
               output: '@BASENAME@',
               configuration: udev_config,
               install: true,
               install_dir: udevdir / 'rules.d')

generate_hwdb_py = find_program('tools/generate-hwdb.py')
builds = [
    { 'enabled': install_testing, 'suffix': 'testing', 'files': bpf_o_files_testing },
    { 'enabled': install_stable, 'suffix': 'stable', 'files': bpf_o_files_stable },
]

foreach build: builds
    if build['enabled']
        json_data = custom_target(
            'extract json data @0@'.format(build['suffix']),
            depends: cargo_build,
            output: 'bpf-@0@.json'.format(build['suffix']),
            capture: true,
            command: [
                cargo_build,
                'inspect',
                build['files'],
            ]
        )

        # T, S, or U
        suffix = build['suffix'].substring(0, 1).to_upper()
        prop_prefix = 'HID_BPF_@0@_'.format(suffix)

        custom_target(
            'hwdb files @0@'.format(build['suffix']),
            depends: json_data,
            build_by_default: true,
            output: '81-hid-bpf-@0@.hwdb'.format(build['suffix']),
            input: json_data,
            command: [
                generate_hwdb_py,
                '--prefix', prop_prefix,
            ],
            feed: true,
            capture: true,
            install: true,
            install_dir: udevdir / 'hwdb.d',
        )
    endif
endforeach

man_config = configuration_data()
man_config.set('VERSION', meson.project_version())
configure_file(input: 'udev-hid-bpf.man',
               output : '@BASENAME@.1',
               configuration : man_config,
               install_dir : man1dir)

kernel_version = 'unknown'
uname = find_program('uname', required: false)
if uname.found()
    uname_result = run_command(uname, '-r', check: false, capture: true)
    if uname_result.returncode() == 0
        kernel_version = uname_result.stdout().strip()
        if kernel_version.version_compare('< 6.3')
            warning('kernel version is @0@ but we require 6.3 or later.'.format(kernel_version))
        endif
    endif
endif

subdir('test')

summary({'kernel version': kernel_version}, section: 'Host machine')
summary({'udevdir': udevdir,
         'prefix': prefix,
         'bindir': bindir,
         'bpfdir': bpfdir,
         'bpf lookup dirs': lookup_bpfdirs,
         }, section: 'Directories')
