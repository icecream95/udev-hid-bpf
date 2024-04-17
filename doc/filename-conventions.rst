.. _filename_conventions:

Filename conventions
====================


``udev-hid-bpf`` uses this filename convention for all ``.bpf.o`` files it
provides::

    10-vendor__product.bpf.o

Vendor and product represent the specific device's vendor and product and
``10`` is the version number.

.. note:: The versionless "stem" of the file, ``foo__bar.bpf`` is used as
          identifier by the kernel to spot duplicates.


Versioning files
----------------
We use a simple numeric versioning scheme for all ``bpf.o`` files: a prefix
starting at ``10`` for the initial version, then going up to ``20``, ``30``
etc. for subsequent versions.

Future (higher) versions are for programs that use new kernel features.
For example, we may have the same fix for a device:

- ``10-foo__bar.bpf.o`` using features available since kernel v6.6
- ``20-foo__bar.bpf.o`` using features available since kernel v6.8
- ``30-foo__bar.bpf.o`` using features available since kernel v6.11

The loader will attempt to load these in reverse order. On a system running a
6.8 kernel, i.e. it loads ``30-foo__bar.bpf.o`` first, fails, then loads
``20-foo__bar.bpf.o``. This one succeeds so the loader won't attempt to load
``10-foo__bar.bpf.o``.

This version scheme allows ``udev-hid-bpf`` to work against any kernel version
it has worked against in the past, even as programs get updated to make use of
new features.

Note that ``.bpf.o`` files merged into the kernel drop the version prefix as
they will be bound to that particular version.

We use jumps by 10 for each version so that we can slot in another version in
between if required in the future.


Vendor and Product naming guidelines
------------------------------------

The vendor name should be the colloquial reference, e.g. ``HP``, ``Microsoft``,
``Logitech``, ``Wacom``, etc. without trademark symbol, ``Inc.`` suffix, etc.

Where the product has a technical model name it's best to use the marketing
name. Where the same name is used for multiple models, suffix the model name.
And example would be ``10-Wacom__Intuos-Pro2-CTH660.bpf.o``. This makes the
files easy to find by humans but stills specific enough that we can distinguish
which device these apply to.

Note that these rules are just guidelines, there are ``.bpf.o`` files that will
apply to multiple devices so the naming will always be an approximation
only.
