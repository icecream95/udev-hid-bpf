sources = [
    '10-Logitech-MX-Master-3B-middle-button.bpf.c',
    '10-mouse_invert_y.bpf.c',
    '10-trace_hid_events.bpf.c',
    '10-noop-probe-fail.bpf.c',
    '10-noop-probe-succeed.bpf.c',
]

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': have_filters,
            'build_by_default': true,
        },
    ]
endforeach
