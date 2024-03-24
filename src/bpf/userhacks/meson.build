if not build_userhacks
    subdir_done()
endif

sources = files(
    'trace_hid_events.bpf.c',
    'G10-Mechanical-Gaming-Mouse.bpf.c'
)

foreach bpf : sources
    bpf_sources += bpf
    bpf_copied_sources += fs.copyfile(bpf)
endforeach
