# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '10-Huion__H610-Pro.bpf.c',
    '10-Logitech-MX-Master-3B-middle-button.bpf.c',
    '10-mouse_invert_y.bpf.c',
    '10-trace_hid_events.bpf.c',
    '10-noop-probe-fail.bpf.c',
    '10-noop-probe-succeed.bpf.c',
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
