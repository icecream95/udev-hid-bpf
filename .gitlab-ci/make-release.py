#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Script to help create a release tarball for udev-hid-bpf.
# Copies all items in INSTALL_TREE to the given target directory
# and generates the install.sh/uninstall.sh files based on
# the files in that tree.
#
# INSTALL_TREE must be a clean install tree with nothing but the udev-hid-bpf
# files.

from dataclasses import dataclass
from pathlib import Path

import argparse
import jinja2
import jinja2.environment
import shutil
import logging


logger = logging.getLogger("")
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logger.setLevel(logging.INFO)

parser = argparse.ArgumentParser(
    description="Creates a release tree from an installed udev-hid-bpf directory"
)
parser.add_argument("--verbose", action="store_true", default=False)
parser.add_argument(
    "--templates",
    action="append",
    type=Path,
    help="A jinja template to parse and place in the top-level directory of the TARGET_DIR",
)
parser.add_argument(
    "source_dir",
    metavar="INSTALL_TREE",
    type=Path,
    help="A meson install-ed tree of udev-hid-bpf",
)
parser.add_argument(
    "target_dir",
    metavar="TARGET_DIR",
    type=Path,
    help="Target directory to place all files",
)
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)


@dataclass
class InstallFile:
    path: Path

    @property
    def dir(self) -> Path:
        return self.path.parent

    @property
    def filename(self) -> str:
        return self.path.name


bpfs = []
udev_rules = []
hwdb_files = []
# First copy our installed tree over
for file in args.source_dir.glob("**/*"):
    if file.is_dir():
        continue

    path = file.relative_to(args.source_dir)
    target = args.target_dir / path
    target.parent.mkdir(exist_ok=True, parents=True)
    logger.debug(f"{target}")
    shutil.copyfile(file, target)
    shutil.copymode(file, target)

    ifile = InstallFile(target.relative_to(args.target_dir))

    if target.name.endswith(".bpf.o"):
        bpfs.append(ifile)
    elif target.name.endswith(".rules"):
        udev_rules.append(ifile)
    elif target.name.endswith(".hwdb"):
        hwdb_files.append(ifile)


data = {"bpfs": bpfs, "udev_rules": udev_rules, "hwdb_files": hwdb_files}

for template in args.templates:
    template_dir = template.absolute().parent
    loader = jinja2.FileSystemLoader(template_dir)
    env = jinja2.Environment(
        loader=loader,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    jtemplate = env.get_template(template.name)
    stream = jtemplate.stream(data)
    target = args.target_dir / template.name.rstrip(".jinja")
    logger.debug(target)
    with open(target, "w") as fd:
        stream.dump(fd)
    shutil.copymode(template, target)
