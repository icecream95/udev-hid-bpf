if not build_stable
    subdir_done()
endif

sources = [
]

foreach bpf : sources
    filter_matches = not have_filters
    if have_filters
        foreach filter : filters
            if bpf.contains(filter)
                filter_matches = true
                break
            endif
        endforeach
    endif
    if filter_matches
        bpf_sources += files(bpf)
        bpf_copied_sources += fs.copyfile(bpf)
    endif
endforeach
