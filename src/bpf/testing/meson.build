if not build_testing
    subdir_done()
endif

sources = [
    'HP_Elite_Presenter.bpf.c',
    'Kaliber-MMOmentum.bpf.c',
    'XBox_Elite_2.bpf.c',
    'xppen-Artist24.bpf.c',
    'xppen-ArtistPro16Gen2.bpf.c',
]

foreach bpf : sources
    filter_matches = not have_filters
    if have_filters
        foreach filter: filters
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
