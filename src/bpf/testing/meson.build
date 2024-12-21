# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0020-XPPen__ArtistPro16Gen2.bpf.c',
    '0010-Huion__KeydialK20.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
     '0010-ASUS__Vivobook_S15_S5507_kbd.bpf.c',
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'section': 'testing',
                'file': files(bpf)[0],
                'install': install_testing,
                'build_by_default': install_testing,
                'compile_with_tracing': true,
            },
        ]
    endif
endforeach

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
endforeach
