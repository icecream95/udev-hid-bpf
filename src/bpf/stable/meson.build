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

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': install_stable,
        },
    ]
endforeach
