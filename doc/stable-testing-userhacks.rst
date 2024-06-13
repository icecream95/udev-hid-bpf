.. _stable_testing_userhacks:

Quirks, user hacks, testing and stable
======================================

``udev-hid-bpf`` divides HID-BPF programs into two categories: quirks and user hacks. Quirks are programs that
fix a device that objectively has a hardware or firmware bug. Examples include axis that are inverted, provide
the wrong ranges/values or event sequences that are logically impossible.
We expect that quirks are eventually upstreamed into the kernel.

User hacks are HID-BPF programs that change a user-subjective preference on a device. Examples include swapping
buttons for convenience or muting an axis to avoid crashes in a specific application. These programs will
never be upstreamed as they are user and use-case specific. ``udev-hid-bpf`` maintains a set of user hacks
as examples and starting point for users who want to develop their own hacks.

To divide this we use the following directory structure:

- ``bpf/testing/`` is where all new quirks should go. Once they have proven to
  be good enough, they should be submitted to the upstream kernel. Distributions
  that package ``udev-hid-bpf`` may make these quirks available but should not
  require them.
- ``bpf/stable/`` is where quirks move to once upstream has accepted them and
  they will be part of the next kernel release.  Distributions that package
  ``udev-hid-bpf`` should package these stable quirks.
- ``bpf/userhacks`` is where all user hacks should go. Unlike quirks these will
  never move to stable. It is not recommended that distributions package userhacks.


Installing testing or stable
----------------------------

By default, only ``testing`` is enabled during ``meson setup``. To select which one to install, run
``meson configure -Dbpfs=testing,stable builddir/`` (or a subset
thereof) or pass ``-Dbpfs`` to the initial ``meson setup`` call. Note that
userhacks cannot be selected as a whole and have to be built and installed individually.


Installing individual HID-BPF programs
--------------------------------------

To build and install only one specific file use the ``-Dfilter-bpf`` option. This option takes one or more comma-separated strings,
any ``bpf.c`` file that contains one of the strings will be installed. For example,
to build and install all BPF files with ``Foo`` or ``Bar`` in their file name use ``-Dfilter-bpf=Foo,Bar``.
Specifying a filter automatically enables all of testing, stable and userhacks but only the matching files will be installed.


Rebuilding
----------

Note that all the ``bpf.c`` files that are known to meson (so registered in ``src/bpf/*/meson.build``) are recompiled
when there is a change. So for ``bpf/userhacks``, in most cases, no meson option needs to be added: just recompile
with ``ninja`` and then use ``udev-hid-bpf install ./builddir/src/bpf/my_awesome_hid_bpf_filter.bpf.o``.
