fs = import('fs')

# copied from systemd meson.build
c_args = get_option('c_args')
bpf_compiler = get_option('bpf-compiler')
libbpf = dependency('libbpf',
                    required : true,
                    version : bpf_compiler == 'gcc' ? '>= 1.4.0' : '>= 0.1.0')

if bpf_compiler == 'clang'
        # Support 'versioned' clang/llvm-strip binaries, as seen on Debian/Ubuntu
        # (like clang-10/llvm-strip-10)
        if meson.is_cross_build() or cc.get_id() != 'clang' or cc.cmd_array()[0].contains('afl-clang') or cc.cmd_array()[0].contains('hfuzz-clang')
                clang = find_program('clang',
                                     required : true,
                                     version : '>= 10.0.0')
        else
                clang = cc.cmd_array()
        endif

        # Check if 'clang -target bpf' is supported.
        run_command(clang, '-target', 'bpf', '--print-supported-cpus', check : true)
elif bpf_compiler == 'gcc'
        bpf_gcc = find_program('bpf-gcc',
                               'bpf-none-gcc',
                               required : true,
                               version : '>= 13.1.0')
else
        error('Unsupported bpf_compiler option')
endif

# Debian installs this in /usr/sbin/ which is not in $PATH.
# We check for 'bpftool' first, honouring $PATH, and in /usr/sbin/ for Debian.
# We use 'bpftool gen object' subcommand for bpftool strip, it was added by d80b2fcbe0a023619e0fc73112f2a02c2662f6ab (v5.13).
bpftool = find_program('bpftool',
                       '/usr/sbin/bpftool',
                       required : true,
                       version : bpf_compiler == 'gcc' ? '>= 7.0.0' : '>= 5.13.0')

bpf_clang_flags = [
        '-std=gnu11',
        '-Wno-compare-distinct-pointer-types',
        '-fno-stack-protector',
        '-O2',
        '-target',
        'bpf',
        '-g',
        '-c',
]

bpf_gcc_flags = [
        '-std=gnu11',
        '-fno-stack-protector',
        '-fno-ssa-phiopt',
        '-O2',
        '-mcpu=v3',
        '-mco-re',
        '-gbtf',
        '-c',
]

# If c_args contains these flags copy them along with the values, in order to avoid breaking
# reproducible builds and other functionality
propagate_cflags = [
        '-ffile-prefix-map=',
        '-fdebug-prefix-map=',
        '-fmacro-prefix-map=',
]

foreach opt : c_args
        foreach flag : propagate_cflags
                if opt.startswith(flag)
                        bpf_clang_flags += [opt]
                        bpf_gcc_flags += [opt]
                        break
                endif
        endforeach
endforeach

# Generate defines that are appropriate to tell the compiler what architecture
# we're compiling for. By default we just map meson's cpu_family to __<cpu_family>__.
# This dictionary contains the exceptions where this doesn't work.
#
# C.f. https://mesonbuild.com/Reference-tables.html#cpu-families
# and src/basic/missing_syscall_def.h.
cpu_arch_defines = {
        'ppc'     : ['-D__powerpc__'],
        'ppc64'   : ['-D__powerpc64__', '-D_CALL_ELF=2'],
        'riscv32' : ['-D__riscv', '-D__riscv_xlen=32'],
        'riscv64' : ['-D__riscv', '-D__riscv_xlen=64'],
        'x86'     : ['-D__i386__'],
        's390x'   : ['-D__s390__', '-D__s390x__'],

        # For arm, assume hardware fp is available.
        'arm'     : ['-D__arm__', '-D__ARM_PCS_VFP'],
}

bpf_arch_flags = cpu_arch_defines.get(host_machine.cpu_family(),
                                      ['-D__@0@__'.format(host_machine.cpu_family())])
if bpf_compiler == 'gcc'
        bpf_arch_flags += ['-m' + host_machine.endian() + '-endian']
endif

libbpf_include_dir = libbpf.get_variable(pkgconfig : 'includedir')

bpf_o_unstripped_cmd = []
if bpf_compiler == 'clang'
        bpf_o_unstripped_cmd += [
                clang,
                bpf_clang_flags,
                bpf_arch_flags,
        ]
elif bpf_compiler == 'gcc'
        bpf_o_unstripped_cmd += [
                bpf_gcc,
                bpf_gcc_flags,
                bpf_arch_flags,
        ]
endif

bpf_o_unstripped_cmd += ['-I.']

if not meson.is_cross_build()
        target_triplet_cmd = run_command('gcc', '-dumpmachine', check: false)
        if target_triplet_cmd.returncode() == 0
                target_triplet = target_triplet_cmd.stdout().strip()
                bpf_o_unstripped_cmd += [
                        '-isystem',
                        '/usr/include/@0@'.format(target_triplet)
                ]
        endif
endif

bpf_o_unstripped_cmd += [
        '-idirafter',
        libbpf_include_dir,
        '@INPUT@',
        '-o',
        '@OUTPUT@'
]

bpf_o_cmd = [
        bpftool,
        'gen',
        'object',
        '@OUTPUT@',
        '@INPUT@'
]

skel_h_cmd = [
        bpftool,
        'gen',
        'skeleton',
        '@INPUT@'
]

use_provided_vmlinux_h = false
use_generated_vmlinux_h = false
provided_vmlinux_h_path = get_option('vmlinux-h-path').replace('@SOURCE_DIR@', meson.project_source_root())

# For the more complex BPF programs we really want a vmlinux.h (which is arch
# specific, but only somewhat bound to kernel version). Ideally the kernel
# development headers would ship that, but right now they don't. Hence address
# this in two ways:
#
# 1. Provide a vmlinux.h at build time
# 2. Generate the file on the fly where possible (which requires /sys/ to be mounted)
#
# We generally prefer the former (to support reproducible builds), but will
# fallback to the latter.

enable_vmlinux_h = get_option('vmlinux-h')

if enable_vmlinux_h == 'auto'
        if provided_vmlinux_h_path != ''
                use_provided_vmlinux_h = true
        elif fs.exists('/sys/kernel/btf/vmlinux') and \
                        bpftool.found() and \
                        (host_machine.cpu_family() == build_machine.cpu_family()) and \
                        host_machine.cpu_family() in ['x86_64', 'aarch64']

                # We will only generate a vmlinux.h from the running
                # kernel if the host and build machine are of the same
                # family. Also for now we focus on x86_64 and aarch64,
                # since other archs don't seem to be ready yet.

                use_generated_vmlinux_h = true
        endif
elif enable_vmlinux_h == 'provided'
        use_provided_vmlinux_h = true
elif enable_vmlinux_h == 'generated'
        if not fs.exists('/sys/kernel/btf/vmlinux')
                error('BTF data from kernel not available (/sys/kernel/btf/vmlinux missing), cannot generate vmlinux.h, but was asked to.')
        endif
        if not bpftool.found()
                error('bpftool not available, cannot generate vmlinux.h, but was asked to.')
        endif
        use_generated_vmlinux_h = true
endif

if use_provided_vmlinux_h
        if not fs.exists(provided_vmlinux_h_path)
                error('Path to provided vmlinux.h does not exist.')
        endif
        vmlinux_h_dependency = []
        bpf_o_unstripped_cmd += ['-I' + fs.parent(provided_vmlinux_h_path)]
        message('Using provided @0@'.format(provided_vmlinux_h_path))
elif use_generated_vmlinux_h
        vmlinux_h_dependency = custom_target(
                'vmlinux.h',
                output: 'vmlinux.h',
                command : [ bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c' ],
                capture : true)

        bpf_o_unstripped_cmd += ['-I' + fs.parent(vmlinux_h_dependency.full_path())]
        message('Using generated @0@'.format(vmlinux_h_dependency.full_path()))
else
        error('Using neither provided nor generated vmlinux.h, some features will not be available.')
endif

#####################################################################

# We need to append the bpf dir after the possibly generated vmlinux.h
bpf_o_unstripped_cmd += ['-I' + meson.project_source_root() / 'src' / 'bpf']

bpf_tracing_o_unstripped_cmd = bpf_o_unstripped_cmd + ['-DHID_BPF_TRACING']

filters = get_option('bpf-filter')
have_filters = filters != []

subset = get_option('bpfs')
install_testing = 'testing' in subset or have_filters
install_stable = 'stable' in subset or have_filters

bpf_o_files_testing = []
bpf_o_files_stable = []
bpf_o_files_userhacks = []

prefix = get_option('prefix')
bpfdir = prefix / 'lib' / 'firmware' / 'hid' / 'bpf'

bpf_sources = []

subdir('testing')
subdir('stable')
subdir('userhacks')

bpf_objects = []

foreach bpf_source : bpf_sources
    bpf = bpf_source['name']
    file = bpf_source['file']
    outdir = fs.parent(file)
    kind = fs.name(outdir)
    install = bpf_source['install']
    build_by_default = bpf_source.get('build_by_default', false)
    compile_with_tracing = bpf_source['compile_with_tracing']

    bpf_splitted = bpf.split('-')
    id = bpf_splitted[0].to_int()
    # we remove the first numbers, the first '-' and the last 2 chars for '.c'
    stem = bpf.strip('0123456789').substring(1, -2)

    cmd = bpf_o_unstripped_cmd

    # Build with an id lower than struct_ops so loading always prefers
    # struct_ops and only falls back to tracing where struct_ops fails
    if compile_with_tracing
        id = id - 1
        cmd = bpf_tracing_o_unstripped_cmd
    endif

    if id < 10
        file_id = f'0@id@'
    else
        file_id = f'@id@'
    endif


    filter_matches = not have_filters
    if have_filters
        foreach filter: filters
            if bpf.contains(filter)
                filter_matches = true
                break
            endif
        endforeach
    endif


    unstripped_bpf = custom_target(
        input : file,
        output: ['@0@-@1@.unstripped.o'.format(file_id, stem)],
        command : cmd,
        depends : vmlinux_h_dependency)

    bpf_o_file = '@0@-@1@.o'.format(file_id, stem)

    bpf_o = custom_target(
        input: unstripped_bpf,
        depend_files: file,
        output: [bpf_o_file],
        command : bpf_o_cmd,
        install: install and filter_matches,
        install_dir: bpfdir,
        build_by_default: build_by_default,
    )

    if kind == 'stable'
        bpf_o_files_stable += bpf_o
    elif kind == 'testing'
        bpf_o_files_testing += bpf_o
    elif kind == 'userhacks'
        bpf_o_files_userhacks += bpf_o
    endif

    bpf_objects += [{ 'file': file, 'bpf_o': bpf_o, 'output_file': bpf_o_file },]
endforeach
