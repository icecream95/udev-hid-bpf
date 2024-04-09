#!/bin/bash

if [ -z "$KERNEL_URL" ]; then
  echo "ERRROR: \$KERNEL_URL must be set"
fi

if [ -z "$KERNEL_VERSION" ]; then
  echo "ERRROR: \$KERNEL_VERSION must be set"
fi

if [ -z "$CI" ]; then
  CI_JOB_TOKEN=$(uuidgen)
  DRY_RUN="echo"
fi

set -ex
echo -e "section_start:`date +%s`:check\r\e[0KCheck for existing bzImage"
curl --header "JOB-TOKEN: $CI_JOB_TOKEN" -LO $KERNEL_URL

# the kernel is already published, abort
# -> if the file type is not 'kernel', file|grep
# is true, otherwise, exit 0
file bzImage | grep -v kernel || exit 0

echo -e "section_end:`date +%s`:check\r\e[0K"

echo -e "section_start:`date +%s`:download\r\e[0KDownload and unpack kernel sources"
curl -LO https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION/.*/}.x/linux-${KERNEL_VERSION}.tar.xz

tar xf linux-${KERNEL_VERSION}.tar.xz
echo -e "section_end:`date +%s`:download\r\e[0K"

cd linux-${KERNEL_VERSION}

echo -e "section_start:`date +%s`:build[collapsed=true]\r\e[0KBuild the kernel"
../.gitlab-ci/make-config.sh

make -j${FDO_CI_CONCURRENT:-4} bzImage
echo -e "section_end:`date +%s`:build\r\e[0K"

echo -e "section_start:`date +%s`:upload\r\e[0KUpload the kernel"
$DRY_RUN curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
     --upload-file ./arch/$(arch)/boot/bzImage\
     $KERNEL_URL | tee upload.txt

# check that the upload was successful
grep '201 Created' upload.txt
echo -e "section_end:`date +%s`:upload\r\e[0K"
