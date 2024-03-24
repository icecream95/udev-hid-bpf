# cargo runs in the build tree so we copy our source tree over
sources = files('attach.bpf.c')
foreach bpf : sources
    fs.copyfile(bpf)
endforeach

subdir('testing')
subdir('stable')
subdir('userhacks')
