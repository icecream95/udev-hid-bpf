#!/bin/bash

# set exit on failure
set -e

function insert_kernel_options {
  opts=$(echo $@ | tr '\n' ' ')

  for o in ${opts}
  do
    echo $o >> .config
  done

  make olddefconfig

  RET=0

  for o in ${opts}
  do
    if [ -z "$(grep ^$o .config)" ]
    then
      echo "$o missing in .config"
      RET=1
    fi
  done

  return $RET
}

make $(arch)_defconfig

# disable WERROR
sed -i 's/CONFIG_WERROR=y/# CONFIG_WERROR is not set/' .config

# we need the following base config:
# - virtio for network communication
# - cgroups for podman
# - namespaces for podman
# - overlayfs for podman
BASE_OPTS="
  CONFIG_TTY=y
  CONFIG_PCI=y
  CONFIG_BLOCK=y
  CONFIG_NETDEVICES=y
  CONFIG_HUGETLBFS=y

  CONFIG_VIRTIO=y
  CONFIG_VIRTIO_MENU=y
  CONFIG_VIRTIO_PCI=y
  CONFIG_VIRTIO_NET=y
  CONFIG_VIRTIO_BLK=y
  CONFIG_VIRTIO_CONSOLE=y
  CONFIG_FUSE_FS=y
  CONFIG_VIRTIO_FS=y

  CONFIG_CGROUPS=y
  CONFIG_BLK_CGROUP=y
  CONFIG_CGROUP_WRITEBACK=y
  CONFIG_CGROUP_SCHED=y
  CONFIG_CGROUP_PIDS=y
  CONFIG_CGROUP_FREEZER=y
  CONFIG_HUGETLB_PAGE=y
  CONFIG_CGROUP_HUGETLB=y
  CONFIG_CGROUP_DEVICE=y
  CONFIG_CGROUP_CPUACCT=y
  CONFIG_CGROUP_PERF=y
  CONFIG_CGROUP_DEBUG=y
  CONFIG_SOCK_CGROUP_DATA=y
  CONFIG_MEMCG=y
  CONFIG_NET=y
  CONFIG_NET_SCHED=y
  CONFIG_NET_CLS_CGROUP=y
  CONFIG_CGROUP_NET_CLASSID=y
  CONFIG_CGROUP_NET_PRIO=y

  CONFIG_MULTIUSER=y

  CONFIG_NAMESPACES=y
  CONFIG_USER_NS=y

  CONFIG_OVERLAY_FS=y
"

insert_kernel_options $BASE_OPTS

# BPF specific options
BPF_OPTS="
  CONFIG_BPF_EVENTS=y
  CONFIG_BPF_JIT_ALWAYS_ON=y
  CONFIG_BPF_JIT=y
  CONFIG_BPF_STREAM_PARSER=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF=y
  CONFIG_CGROUP_BPF=y
  CONFIG_COMPILE_TEST=y
  CONFIG_DEBUG_INFO_DWARF5=y
  CONFIG_DEBUG_INFO_BTF=y
  CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
  CONFIG_FPROBE=y
  CONFIG_FTRACE_SYSCALLS=y
  CONFIG_FUNCTION_TRACER=y
"

insert_kernel_options $BPF_OPTS

# input specific options
INPUT_OPTS="
  CONFIG_GPIOLIB=y

  CONFIG_USB=y
  CONFIG_USB_SUPPORT=y
  CONFIG_USB_XHCI_HCD=y
  CONFIG_USB_EHCI_HCD=y
  CONFIG_USB_UHCI_HCD=y
  CONFIG_USB_OHCI_HCD=y

  CONFIG_I2C=y

  CONFIG_UHID=y
  CONFIG_USB_HID=y
  CONFIG_I2C_HID_CORE=y
  CONFIG_I2C_HID_ACPI=y
  CONFIG_HIDRAW=y
  CONFIG_HID_BATTERY_STRENGTH=y
  CONFIG_HID_GENERIC=y
  CONFIG_USB_HIDDEV=y

  CONFIG_INPUT_EVDEV=y
  CONFIG_INPUT_MISC=y
  CONFIG_INPUT_UINPUT=y

  CONFIG_LEDS_CLASS_MULTICOLOR=y

  CONFIG_HID_BPF=y
"

insert_kernel_options $INPUT_OPTS

# change the local version
LOCAL_OPTS="
  CONFIG_LOCALVERSION=\"-CI-PIPELINE-$CI_PIPELINE_ID\"
"

insert_kernel_options $LOCAL_OPTS

for i in 0 1 2
do
  # switch all HID to y
  sed -i -E 's/^# CONFIG_HID(.*) is not set/CONFIG_HID\1=y/' .config

  # force the HID_FF modules to be set
  sed -i -E 's/^# CONFIG_(.*_FF) is not set/CONFIG_\1=y/' .config

  # check for new CONFIGS
  make olddefconfig
done
