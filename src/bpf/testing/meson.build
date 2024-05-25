sources = [
    '10-Huion__Inspiroy-2-S.bpf.c',
    '10-XPPen__DecoMini4.bpf.c',
]

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': install_testing,
        },
    ]
endforeach
