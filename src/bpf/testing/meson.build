sources = [
    '10-Huion__Inspiroy-2-S.bpf.c'
]

foreach bpf : sources
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
        '@0@.unstripped.o'.format(bpf),
        input : bpf,
        output: ['@BASENAME@.unstripped.o'],
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

    bpf_o_files_testing += custom_target(
        '@0@.o'.format(bpf),
        input: unstripped_bpf,
        depend_files: bpf,
        output: ['@0@.o'.format(bpf.substring(0, -2))],
        command : bpf_o_cmd,
        install: install_testing and filter_matches,
        install_dir: bpfdir,
    )
endforeach
