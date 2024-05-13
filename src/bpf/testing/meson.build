# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '10-Huion__Dial-2.bpf.c',
    '10-Huion__Inspiroy-2-S.bpf.c',
    '10-Thrustmaster__TCA-Yoke-Boeing.bpf.c',
    '10-XPPen__DecoMini4.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': install_testing,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'file': files(bpf)[0],
                'install': install_testing,
                'compile_with_tracing': true,
            },
        ]
    endif
endforeach

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': install_testing,
            'compile_with_tracing': false,
        },
    ]
endforeach
