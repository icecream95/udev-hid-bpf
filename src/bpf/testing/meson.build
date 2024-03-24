if not build_testing
    subdir_done()
endif

sources = files(
    'HP_Elite_Presenter.bpf.c',
    'Kaliber-MMOmentum.bpf.c',
    'XBox_Elite_2.bpf.c',
    'xppen-Artist24.bpf.c',
    'xppen-ArtistPro16Gen2.bpf.c',
)

foreach bpf : sources
    bpf_sources += bpf
    bpf_copied_sources += fs.copyfile(bpf)
endforeach
