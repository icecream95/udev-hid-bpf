if not build_stable
    subdir_done()
endif

sources = files(
)

foreach bpf : sources
    bpf_sources += bpf
    bpf_copied_sources += fs.copyfile(bpf)
endforeach
