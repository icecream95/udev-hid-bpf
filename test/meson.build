libbpf_dep = dependency('libbpf', required: get_option('tests'))
pytest = find_program('pytest-3', 'pytest', required: get_option('tests'))
pymod = import('python')
python = pymod.find_installation('python3', required: get_option('tests'))

build_tests = libbpf_dep.found() and pytest.found() and python.found()
if not build_tests
    subdir_done()
endif

# We recompile the BPF as a normal shared library, one
# per BPF program.
foreach f: bpf_sources
    src = ['test-wrapper.c'] + f
    fname = fs.stem(f)
    fname = fs.stem(fname)
    fname = fs.name(fname)
    shared_library('test-@0@'.format(fname),
        src,
        c_args : ['-Wno-unknown-pragmas'],
        include_directories: include_directories('../src/bpf/'),
        install: false,
    )
endforeach

env = environment()
env.set('LD_LIBRARY_PATH', meson.current_build_dir())
pymod.find_installation(modules: ['pytest'])
test('pytest',
    pytest,
    args: [
        '--verbose',
        '-rfES',
        '--log-level=DEBUG',
        '--log-file', meson.project_build_root() / 'meson-logs' / 'pytest.log',
        '--log-file-level=DEBUG',
    ],
    env: env,
    workdir: meson.project_source_root()
)
