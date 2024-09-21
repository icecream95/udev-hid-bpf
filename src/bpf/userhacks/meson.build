# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0010-Huion__H610-Pro.bpf.c',
    '0010-Logitech-MX-Master-3B-middle-button.bpf.c',
    '0010-Logitech-MX-Master-3S-horiz-scroll.bpf.c',
    '0010-QuinHeng__PCsensor-FootSwitch.bpf.c',
    '0010-mouse_invert_y.bpf.c',
    '0010-trace_hid_events.bpf.c',
    '0010-noop-probe-fail.bpf.c',
    '0010-noop-probe-succeed.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
    '0010-Microsoft__Surface_Dial.bpf.c',
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'file': files(bpf)[0],
            'install': have_filters,
            'build_by_default': true,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'file': files(bpf)[0],
                'install': have_filters,
                'build_by_default': true,
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
            'install': have_filters,
            'build_by_default': true,
            'compile_with_tracing': false,
        },
    ]
endforeach
