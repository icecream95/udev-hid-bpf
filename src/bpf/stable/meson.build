sources = [
    '10-FR-TEC__Raptor-Mach-2.bpf.c',
    '10-HP__Elite-Presenter.bpf.c',
    '10-Huion__Kamvas-Pro-19.bpf.c',
    '10-IOGEAR__Kaliber-MMOmentum.bpf.c',
    '10-Microsoft__XBox-Elite-2.bpf.c',
    '10-Wacom__ArtPen.bpf.c',
    '10-XPPen__Artist24.bpf.c',
    '10-XPPen__ArtistPro16Gen2.bpf.c',
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
    bpf_sources += files(bpf)
    unstripped_bpf = custom_target(
        '@0@.unstripped.o'.format(bpf),
        input : bpf,
        output: ['@BASENAME@.unstripped.o'],
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

    bpf_o_files_stable += custom_target(
        '@0@.o'.format(bpf),
        input: unstripped_bpf,
        depend_files: bpf,
        output: ['@0@.o'.format(bpf.substring(0, -2))],
        command : bpf_o_cmd,
        install: install_stable and filter_matches,
        install_dir: bpfdir,
    )
endforeach
