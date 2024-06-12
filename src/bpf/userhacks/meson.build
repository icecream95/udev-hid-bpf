sources = [
    '10-Logitech-MX-Master-3B-middle-button.bpf.c',
    '10-mouse_invert_y.bpf.c',
    '10-trace_hid_events.bpf.c',
    '10-noop-probe-fail.bpf.c',
    '10-noop-probe-succeed.bpf.c',
]

foreach bpf : sources
    filter_matches = false
    if have_filters
        foreach filter : filters
            if bpf.contains(filter)
                filter_matches = true
                break
            endif
        endforeach
    endif
    bpf_sources += files(bpf)
    unstripped_bpf = custom_target(
        '@0@.unstripped.o'.format(bpf),
        input : bpf,
        output: ['@BASENAME@.unstripped.o'],
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

    bpf_o_files_userhacks += custom_target(
        '@0@.o'.format(bpf),
        input: unstripped_bpf,
        depend_files: bpf,
        output: ['@0@.o'.format(bpf.substring(0, -2))],
        command : bpf_o_cmd,
        install: have_filters and filter_matches,
        install_dir: bpfdir,
        build_by_default: true,
    )
endforeach
