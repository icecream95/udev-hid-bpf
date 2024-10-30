# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0010-FR-TEC__Raptor-Mach-2.bpf.c',
    '0010-HP__Elite-Presenter.bpf.c',
    '0010-Huion__Dial-2.bpf.c',
    '0010-Huion__Inspiroy-2-S.bpf.c',
    '0010-Huion__Kamvas-Pro-19.bpf.c',
    '0010-IOGEAR__Kaliber-MMOmentum.bpf.c',
    '0010-Microsoft__Xbox-Elite-2.bpf.c',
    '0010-Mistel__MD770.bpf.c',
    '0010-Rapoo__M50-Plus-Silent.bpf.c',
    '0010-Thrustmaster__TCA-Yoke-Boeing.bpf.c',
    '0010-Wacom__ArtPen.bpf.c',
    '0010-XPPen__Artist24.bpf.c',
    '0010-XPPen__ArtistPro16Gen2.bpf.c',
    '0010-XPPen__DecoMini4.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'stable',
            'file': files(bpf)[0],
            'install': install_stable,
            'build_by_default': install_stable,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'section': 'stable',
                'file': files(bpf)[0],
                'install': install_stable,
                'build_by_default': install_stable,
                'compile_with_tracing': true,
            },
        ]
    endif
endforeach

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'stable',
            'file': files(bpf)[0],
            'install': install_stable,
            'build_by_default': install_stable,
            'compile_with_tracing': false,
        },
    ]
endforeach
