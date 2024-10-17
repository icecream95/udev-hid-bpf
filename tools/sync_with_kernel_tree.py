#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# semi-automatically prepare the upstreaming of the bpf files into a kernel
# tree branch.
#

from pathlib import Path
from dataclasses import dataclass
import click
import git
import os
import shutil


DEFAULT_KERNEL_PATH = "../hid"


@dataclass
class Repos:
    kernel: git.Repo
    udev_hid_bpf: git.Repo

    @property
    def kernel_bpf_dir(self):
        return Path(self.kernel.working_tree_dir) / "drivers" / "hid" / "bpf" / "progs"


pass_repo = click.make_pass_decorator(Repos)


@click.group()
@click.option(
    "--kernel",
    type=click.Path(exists=True),
    default=Path(DEFAULT_KERNEL_PATH),
    help="Path to the hid.git kernel tree",
)
@click.pass_context
def cli(ctx, kernel):
    script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    git_udev_hid_bpf = git.Repo(script_dir.parent)
    assert not git_udev_hid_bpf.bare
    git_kernel = git.Repo(kernel)
    assert not git_kernel.bare
    ctx.obj = Repos(git_kernel, git_udev_hid_bpf)


@cli.command()
@pass_repo
def to_kernel_tree(repos):
    """prepare commits on a kernel tree

    look for files in src/bpf/testing, fetch each file its git log
    copy those files to the kernel tree and commit the files with
    the content of the commit log.

    """
    if repos.udev_hid_bpf.head.ref.name not in ["main"]:
        click.confirm(
            f"current head ({repos.udev_hid_bpf.head.ref}) is not on 'main', are you sure?",
            abort=True,
        )

    click.confirm(f"currently on {repos.kernel.head.ref}, is that OK?", abort=True)

    # gather commits creating/touching new files that need to be upstreamed
    tree = repos.udev_hid_bpf.head.commit.tree
    blobs = [
        b for b in (tree / "src/bpf/testing").traverse() if b.name != "meson.build"
    ]

    history = {
        blob: repos.udev_hid_bpf.git.log("--pretty=%H", "--follow", blob.path).split(
            "\n"
        )
        for blob in blobs
    }

    # get committer informations
    with repos.kernel.config_reader() as git_config:
        email = git_config.get_value("user", "email")
        user = git_config.get_value("user", "name")

    # copy the files, strip the '00xx-' prefix, and commit
    for blob, hist in history.items():
        source = Path(blob.abspath)
        dest = repos.kernel_bpf_dir / blob.name.lstrip("-0.123456789")
        message = "\n".join([repos.udev_hid_bpf.commit(hash).message for hash in hist])
        message += f"Signed-off-by: {user} <{email}>"

        print(f"copy {source} to {dest}")
        shutil.copy(source, dest)
        repos.kernel.index.add([dest])
        repos.kernel.index.commit(message)


if __name__ == "__main__":
    cli()
