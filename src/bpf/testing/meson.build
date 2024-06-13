sources = [
    '10-Huion__Inspiroy-2-S.bpf.c'
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
