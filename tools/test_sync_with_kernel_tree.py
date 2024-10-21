from click.testing import CliRunner
from dataclasses import dataclass
from pathlib import Path

import git
import pytest
import re
import sync_with_kernel_tree
import sys
import uuid


sync_with_kernel_tree.RUN_IN_PYTEST = True


@dataclass
class VirtualGit:
    kernel: git.Repo
    udev_hid_bpf: git.Repo

    @property
    def kernel_dir(self):
        """The kernel directory."""
        return Path(self.kernel.working_dir)

    @property
    def kernel_hid_bpf_dir(self):
        """The kernel hid-bpf directory."""
        return self.kernel_dir / "drivers" / "hid" / "bpf" / "progs"

    @property
    def udev_hid_bpf_dir(self):
        """The udev_hid_bpf directory."""
        return Path(self.udev_hid_bpf.working_dir)

    @property
    def udev_hid_bpf_bpf_dir(self):
        """The udev_hid_bpf src/bpf directory."""
        return self.udev_hid_bpf_dir / "src" / "bpf"

    def reset(self):
        self.kernel.head.reset(
            self._kernel_initial_commit, index=True, working_tree=True
        )
        for path in self.kernel.untracked_files:
            (self.kernel_dir / path).unlink()
        self.udev_hid_bpf.head.reset(
            self._udev_hid_bpf_initial_commit, index=True, working_tree=True
        )
        for path in self.udev_hid_bpf.untracked_files:
            (self.udev_hid_bpf_dir / path).unlink()


def meson_build_template(tracing_sources=[], sources=[]) -> str:
    tr_srcs = "\n".join([f"    '{e}'," for e in tracing_sources])
    if tracing_sources:
        tr_srcs += "\n"
    srcs = "\n".join([f"    '{e}'," for e in sources])
    if sources:
        srcs += "\n"
    return f"""# garbage before sources and tracing_sources

tracing_sources = [
{tr_srcs}]

# some more comments

sources = [
{srcs}]

# rest needs to be there too
"""


@pytest.fixture(scope="session")
def virtual_git(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("git_test_data")
    kernel = git.Repo.init(tmp_path / "kernel", b="main")
    uhb = git.Repo.init(tmp_path / "uhb", b="main")
    vg = VirtualGit(kernel, uhb)

    for repo in [kernel, uhb]:
        with repo.config_writer() as git_config:
            repo_name = Path(repo.working_tree_dir).name
            git_config.set_value("user", "email", f"pytest-{repo_name}@example.com")
            git_config.set_value("user", "name", f"Pytest {repo_name}")

    # initialize udev-hid-bpf fake repo with meson.build and a few files
    files = ["0010-first.bpf.c", "0010-second.bpf.c", "0010-third.bpf.c"]
    for dir in ["stable", "testing"]:
        path = vg.udev_hid_bpf_bpf_dir / dir
        path.mkdir(parents=True)
        meson_build = path / "meson.build"
        txt = (
            meson_build_template(files[:2], files[2:])
            if dir == "stable"
            else meson_build_template()
        )
        meson_build.write_text(txt)
        uhb.index.add([meson_build])
    uhb.index.commit("Initial commit")

    for filename in files:
        new_bpf_file = vg.udev_hid_bpf_bpf_dir / "stable" / filename
        new_bpf_file.write_text(f"random text for {filename}")
        vg.udev_hid_bpf.index.add(new_bpf_file)
        uhb_commit_message = f"initial import of {filename}\n\nSob: me"
        vg.udev_hid_bpf.index.commit(uhb_commit_message)

    vg._udev_hid_bpf_initial_commit = vg.udev_hid_bpf.head.commit

    # initialize kernel fake repo with a few knwon files
    vg.kernel_hid_bpf_dir.mkdir(parents=True)
    for filename in ["Makefile", "README"]:
        file = vg.kernel_hid_bpf_dir / filename
        file.touch()
        kernel.index.add(file)
    kernel.index.commit("initial commit")

    for filename in ["first.bpf.c", "second.bpf.c", "third.bpf.c"]:
        new_bpf_file = vg.kernel_hid_bpf_dir / filename
        new_bpf_file.write_text(f"random text for 0010-{filename}")
        vg.kernel.index.add(new_bpf_file)
        uhb_commit_message = f"initial import of {filename}\n\nSob: me"
        vg.kernel.index.commit(uhb_commit_message)

    vg._kernel_initial_commit = vg.kernel.head.commit

    return vg


def run_cli(virtual_git, command, args):
    _args = [
        "--kernel",
        virtual_git.kernel_dir,
        "--udev-hid-bpf",
        virtual_git.udev_hid_bpf_dir,
        command,
    ]
    _args.extend(args)
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(
        sync_with_kernel_tree.cli,
        _args,
    )


@pytest.mark.parametrize("command", ["to-kernel-tree"])
def test_setup(virtual_git, command):
    """calling the script on already sync-ed trees is a no-op"""
    virtual_git.reset()
    kernel_commit = virtual_git.kernel.head.commit
    udev_hid_bpf_commit = virtual_git.udev_hid_bpf.head.commit
    result = run_cli(virtual_git, command, [])
    print(result.stdout)
    print(result.stderr, file=sys.stderr)
    assert result.exit_code == 0
    assert kernel_commit == virtual_git.kernel.head.commit
    assert udev_hid_bpf_commit == virtual_git.udev_hid_bpf.head.commit


def test_to_kernel_new_file(virtual_git):
    """Add a new testing file and forward it to the kernel"""
    virtual_git.reset()
    kernel_commit = virtual_git.kernel.head.commit
    new_bpf_file = (
        virtual_git.udev_hid_bpf_bpf_dir / "testing" / "0010-Test__pytest.bpf.c"
    )
    text = str(uuid.uuid4())
    new_bpf_file.write_text(text)
    virtual_git.udev_hid_bpf.index.add(new_bpf_file)
    uhb_commit_message = (
        "initial import of 0010-Test__pytest.bpf.c\n\nSob: pytest marker\n"
    )
    virtual_git.udev_hid_bpf.index.commit(uhb_commit_message)
    udev_hid_bpf_commit = virtual_git.udev_hid_bpf.head.commit

    result = run_cli(virtual_git, "to-kernel-tree", [])

    print(result.stdout)
    print(result.stderr, file=sys.stderr)
    assert result.exit_code == 0

    # udev-hid-bpf should be untouched
    assert udev_hid_bpf_commit == virtual_git.udev_hid_bpf.head.commit

    # kernel has seen changes
    assert kernel_commit != virtual_git.kernel.head.commit
    assert uhb_commit_message in virtual_git.kernel.head.commit.message
    new_kernel_file = virtual_git.kernel_hid_bpf_dir / "Test__pytest.bpf.c"
    assert new_kernel_file.exists()
    assert new_kernel_file.read_text() == text


def test_to_kernel_update_file(virtual_git):
    """Update an existing stable file in testing, and forward it to the kernel"""
    virtual_git.reset()
    kernel_commit = virtual_git.kernel.head.commit
    bpf_file = virtual_git.udev_hid_bpf_bpf_dir / "testing" / "0020-first.bpf.c"
    text = str(uuid.uuid4())
    bpf_file.write_text(text)
    virtual_git.udev_hid_bpf.index.add(bpf_file)
    uhb_commit_message = "new version of 0020-first.bpf.c\n\nSob: pytest marker\n"
    virtual_git.udev_hid_bpf.index.commit(uhb_commit_message)
    udev_hid_bpf_commit = virtual_git.udev_hid_bpf.head.commit

    result = run_cli(virtual_git, "to-kernel-tree", [])

    print(result.stdout)
    print(result.stderr, file=sys.stderr)
    assert result.exit_code == 0

    # udev-hid-bpf should be untouched
    assert udev_hid_bpf_commit == virtual_git.udev_hid_bpf.head.commit

    # kernel has seen changes
    assert kernel_commit != virtual_git.kernel.head.commit
    assert uhb_commit_message in virtual_git.kernel.head.commit.message
    sob_indexes = [
        x.start() for x in re.finditer("Sob:", virtual_git.kernel.head.commit.message)
    ]
    assert len(sob_indexes) == 1
    kernel_file = virtual_git.kernel_hid_bpf_dir / "first.bpf.c"
    assert kernel_file.exists()
    assert kernel_file.read_text() == text
