import os
import subprocess
from contextlib import contextmanager
from textwrap import dedent

import pytest

import stbt_rig


@pytest.fixture(scope="function", name="tmpdir")
def fixture_tmpdir():
    with stbt_rig.named_temporary_directory(ignore_errors=True) as d:
        origdir = os.path.abspath(os.curdir)
        try:
            os.chdir(d)
            yield d
        finally:
            os.chdir(origdir)


@pytest.fixture(scope="function", name="test_pack")
def fixture_test_pack(tmpdir):  # pylint: disable=unused-argument
    subprocess.check_call(['git', 'init'])
    subprocess.check_call([
        'git', 'config', 'user.email', 'stbt-rig@stb-tester.com'])
    subprocess.check_call(['git', 'config', 'user.name', 'stbt-rig tests'])

    with open("moo", 'w') as f:
        f.write("Hello!\n")
    subprocess.check_call(['git', 'add', 'moo'])
    subprocess.check_call(['git', 'commit', '-m', 'Test'])

    return stbt_rig.TestPack()


def test_testpack_snapshot_no_change_if_no_commits(test_pack):
    with assert_status_unmodified():
        assert rev_parse("HEAD") == test_pack.take_snapshot()


@contextmanager
def assert_status_unmodified():
    pre_status = subprocess.check_output(["git", "status"])
    yield
    post_status = subprocess.check_output(["git", "status"])
    assert pre_status == post_status


def cat(revision, filename):
    return subprocess.check_output(
        ['git', 'cat-file', 'blob', "%s:%s" % (revision, filename)])


def rev_parse(revision):
    return subprocess.check_output(
        ['git', 'rev-parse', '--verify', revision]).strip()


def test_testpack_snapshot_contains_modifications(test_pack):
    with open("moo", "w") as f:
        f.write("Goodbye!\n")

    with assert_status_unmodified():
        ss = test_pack.take_snapshot()
        assert ss != rev_parse("HEAD")
        assert rev_parse("%s~1" % ss) == rev_parse("HEAD")
        assert cat(ss, 'moo') == "Goodbye!\n"
        assert cat("HEAD", 'moo') == "Hello!\n"


def test_testpack_snapshot_with_untracked_files(test_pack, capsys):
    assert capsys.readouterr() == ("", "")
    with open("other", "w") as f:
        f.write("It's uncommitted\n")

    with assert_status_unmodified():
        orig_sha = rev_parse("HEAD")
        ss = test_pack.take_snapshot()
        # Untracked files aren't included in the snapshot:
        assert orig_sha == ss

    assert capsys.readouterr() == ("", dedent("""\
        stbt-rig: Warning: Ignoring untracked files:

            other

        To avoid this warning add untracked files (with "git add") or add them to .gitignore
        """))
