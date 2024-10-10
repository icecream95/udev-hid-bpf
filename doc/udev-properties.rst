.. _udev_properties:

Handling udev properties in BPF programs
========================================

.. _udev_properties_reading:

Reading udev properties into a BPF
----------------------------------

A BPF program with global variables prefixed with ``UDEV_PROP_`` will see
those variables filled with the values of the respective udev property.
For example to get the udev property ``SUBSYSTEM`` declare this variable:

.. code-block:: c

  char UDEV_PROP_SUBSYSTEM[64];

At load-time this property is filled in with the current value of the property,
e.g. ``"hid"``.  If the property does not exist it is left as-is, zero
initialized.

.. warning:: The array size must be large enough to accommodate the property value.
             ``udev-hid-bpf`` does **not** truncate, instead the property is left
             unset (zeroed out).

``udev-hid-bpf`` uses a simple name match so a BPF can use any udev property
it wishes to. For example, some existing Huion BPF programs use a property
called ``HUION_FIRMWARE_ID`` that is set by an external program::

  $ udevadm info /sys/bus/hid/devices/0003:256C:0066*/
  P: /devices/pci0000:00/0000:00:14.0/usb1/1-8/1-8.1/1-8.1:1.0/0003:256C:0066.000C
  M: 0003:256C:0066.000C
  U: hid
  V: hid-generic
  ...
  E: HUION_FIRMWARE_ID=HUION_T21j_221221
  E: HUION_MAGIC_BYTES=1403007d00204e00ff1fd8130306008004006308

This property is then used to detect whether the BPF in question can work
with this device.

.. code-block:: c

  char UDEV_PROP_HUION_FIRMWARE_ID[64];

  SEC("syscall")
  int probe(struct hid_bpf_probe_args *ctx)
  {
      // firmware id has to match T21 for us to attach
      if (UDEV_PROP_HUION_FIRMWARE_ID[6] == 'T' &&
          UDEV_PROP_HUION_FIRMWARE_ID[7] == '2' &&
          UDEV_PROP_HUION_FIRMWARE_ID[8] == '1')
          ctx->retval = 0;
      else
          ctx->retval = -EINVAL;

      return 0;
  }

.. _udev_properties_passing:

Passing udev properties via the commandline
-------------------------------------------

``udev-hid-bpf add`` supports the ``--property KEY=VALUE`` commandline
argument. Values passed via the commandline work identical to
udev properties (but take precendence over udev properties).

For example, the following invocation overrides the ``NAME`` and ``SUBSYTEM``
udev property::

  $ udev-hid-bpf add --property NAME=MyDevice --property SUBSYTEM=hid /sys/bus/hid/devices/0003:256C:0066

This approach can be used as convenient configuration mechanism, in particular
for :ref:`userhacks <stable_testing_userhacks>`.
