#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# semi-automatically prepare the upstreaming of the bpf files into a kernel
# tree branch.
#

from pathlib import Path
from dataclasses import dataclass
import click
import difflib
import filecmp
import git
import os
import shutil
import sys


DEFAULT_KERNEL_PATH = "../hid"
RUN_IN_PYTEST = False


@dataclass
class Repos:
    kernel: git.Repo
    udev_hid_bpf: git.Repo

    @property
    def kernel_bpf_dir(self):
        return Path(self.kernel.working_tree_dir) / "drivers" / "hid" / "bpf" / "progs"


pass_repo = click.make_pass_decorator(Repos)
script_dir = Path(os.path.dirname(os.path.realpath(__file__)))


@click.group()
@click.option(
    "--kernel",
    type=click.Path(exists=True),
    default=Path(DEFAULT_KERNEL_PATH),
    help="Path to the hid.git kernel tree",
)
@click.option(
    "--udev-hid-bpf",
    type=click.Path(exists=True),
    default=script_dir.parent,
    help="Path to the udev-hid-bpf tree",
)
@click.pass_context
def cli(ctx, kernel, udev_hid_bpf):
    git_udev_hid_bpf = git.Repo(udev_hid_bpf)
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
            default=RUN_IN_PYTEST,
            abort=True,
        )

    click.confirm(
        f"currently on {repos.kernel.head.ref}, is that OK?",
        default=RUN_IN_PYTEST,
        abort=True,
    )

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


def confirm_filediff(src: str, dst: str, message: str) -> bool:
    with open(src) as src_f, open(dst) as dst_f:
        s = src_f.readlines()
        d = dst_f.readlines()

    sys.stdout.writelines(difflib.unified_diff(s, d, fromfile=src, tofile=dst))
    print("---")
    return click.confirm(
        message,
        default=RUN_IN_PYTEST,
    )


@cli.command()
@pass_repo
def from_kernel_tree(repos):
    """backport commits from the kernel tree

    look for files in drivers/hid/bpf/progs in the kernel tree, look for
    any differences with src/bpf/stable, and import the changes here.

    """
    click.confirm(
        f"currently on {repos.kernel.head.ref}, is that OK?",
        default=RUN_IN_PYTEST,
        abort=True,
    )

    # gather commits creating/touching new files that need to be upstreamed
    stable_tree = repos.udev_hid_bpf.head.commit.tree
    stable_blobs = [
        b
        for b in (stable_tree / "src/bpf/stable").traverse()
        if b.name != "meson.build"
    ]
    testing_blobs = [
        b
        for b in (stable_tree / "src/bpf/testing").traverse()
        if b.name != "meson.build"
    ]
    common_headers_blobs = [
        b for b in (stable_tree / "src/bpf").traverse() if b.name.endswith(".h")
    ]

    kernel_tree = repos.kernel.head.commit.tree
    kernel_blobs = [
        b
        for b in (kernel_tree / "drivers/hid/bpf/progs").traverse()
        if b.name not in ["Makefile", "README"]
    ]

    # get committer informations
    with repos.udev_hid_bpf.config_reader() as git_config:
        email = git_config.get_value("user", "email")
        user = git_config.get_value("user", "name")

    # iterate over all matching files in the kernel tree
    for blob in kernel_blobs:
        confirm = False

        # gather matching stable and testing files
        stable_matches = [b.abspath for b in stable_blobs if b.name.endswith(blob.name)]
        stable_matches.sort(reverse=True)
        testing_matches = [
            b.abspath for b in testing_blobs if b.name.endswith(blob.name)
        ]
        testing_matches.sort(reverse=True)

        if not stable_matches and not testing_matches and blob.name.endswith(".h"):
            m = [b.abspath for b in common_headers_blobs if b.name == blob.name]
            if m:
                stable_matches = m
                confirm = True

        changes = not stable_matches or any(
            not filecmp.cmp(blob.abspath, m, shallow=False) for m in stable_matches
        )

        if testing_matches:
            if not filecmp.cmp(blob.abspath, testing_matches[0], shallow=False):
                changes = confirm_filediff(
                    testing_matches[0],
                    blob.abspath,
                    f"changes detected in {blob.path}, do you still want to backport them?",
                )

        if not changes:
            continue

        dest = None
        message = None
        idx = 10

        print(f"gathering history of {blob.path}")
        history = repos.kernel.git.log("--pretty=%H", blob.path).split("\n")

        if not stable_matches:
            print(f"new file: {blob.name}")
        else:
            if confirm:
                if not confirm_filediff(
                    stable_matches[0],
                    blob.abspath,
                    f"changes detected in {blob.path}, do you want to backport them?",
                ):
                    # abort backport of current file, and go to the next
                    continue

                dest = stable_matches[0]
            else:
                prev_file = Path(stable_matches[0]).name
                idx = int(prev_file.split("-")[0]) + 10

            with open(stable_matches[0]) as f:
                u = f.readlines()

            new_shas = []

            for sha in history:
                commit = repos.kernel.commit(sha)
                obj = commit.tree / blob.path

                k = obj.data_stream.read().decode("utf-8").splitlines(keepends=True)

                diff = list(difflib.unified_diff(u, k))
                if not diff:
                    break

                new_shas.append(sha)

            if not new_shas:
                commit = repos.kernel.commit(history[0])
                obj = commit.tree / blob.path

                committed_content = (
                    obj.data_stream.read().decode("utf-8").splitlines(keepends=True)
                )
                with open(blob.abspath) as f:
                    current = f.readlines()

                sys.stdout.writelines(
                    difflib.unified_diff(
                        committed_content,
                        current,
                        fromfile=blob.path,
                        tofile="uncommitted content",
                    )
                )
                print("---")

                if not click.confirm(
                    f"Uncommitted changes in {blob.path}, do you want to backport them?",
                    default=RUN_IN_PYTEST,
                ):
                    # abort backport of current file, and go to the next
                    continue

            history = new_shas

        if not dest:
            dest = (
                Path(repos.udev_hid_bpf.working_tree_dir)
                / "src"
                / "bpf"
                / "stable"
                / f"{idx:04}-{blob.name}"
            )

        message = "\n".join(
            [repos.kernel.commit(hash).message.split("---")[0] for hash in history]
        )
        if not message:
            message = "Uncommitted changes\n\n"
        for hash in history:
            message += (
                f"Upstream commit: https://git.kernel.org/hid/hid/c/{hash[:12]}\n"
            )
        message += f"Signed-off-by: {user} <{email}>"

        print(f"copy {blob.path} into {dest}")
        shutil.copy(blob.abspath, dest)
        repos.udev_hid_bpf.index.add([dest])

        tracing_capable = False

        if testing_matches:
            meson_build = (
                Path(repos.udev_hid_bpf.working_tree_dir)
                / "src/bpf/testing/meson.build"
            )
            with open(meson_build) as f:
                meson = f.readlines()
            testing = [Path(file).name for file in testing_matches]
            with open(f"{meson_build}.new", "w") as f:
                in_tracing = False
                for line in meson:
                    found = False
                    if line.strip().startswith("tracing_sources = ["):
                        in_tracing = True
                    if in_tracing and line.strip() == "]":
                        in_tracing = False
                    for file in testing:
                        if file in line:
                            found = True
                            tracing_capable = in_tracing
                            break
                    if not found:
                        f.write(line)
            shutil.move(f"{meson_build}.new", meson_build)
            repos.udev_hid_bpf.index.add([meson_build])

            repos.udev_hid_bpf.index.remove(testing_matches, working_tree=True)

        # manually insert the new file in meson.build:
        # we iterate over meson.build, and when we are
        # between "sources = [" and "]", we gather the
        # list of files, add our current file, sort it,
        # and then re-inject everything
        meson_build = (
            Path(repos.udev_hid_bpf.working_tree_dir) / "src/bpf/stable/meson.build"
        )
        with open(meson_build) as f:
            meson = f.readlines()
        with open(f"{meson_build}.new", "w") as f:
            stable_files = [dest.name]
            found = False
            match = "tracing_sources = [" if tracing_capable else "sources = ["
            for line in meson:
                if line.strip().startswith(match):
                    f.write(line)
                    found = True
                elif found:
                    if line.strip() == "]":
                        stable_files.sort()
                        for n in stable_files:
                            f.write(f"    '{n}',\n")
                        f.write(line)
                        found = False
                    else:
                        stable_files.append(line.strip().strip("',"))
                else:
                    f.write(line)

        shutil.move(f"{meson_build}.new", meson_build)
        repos.udev_hid_bpf.index.add([meson_build])
        repos.udev_hid_bpf.index.commit(message)


if __name__ == "__main__":
    cli()
