import os
import shutil
from textwrap import dedent

import pytest

import stbt_rig

try:
    # Needed for timeout argument to wait on Python 2.7
    import subprocess32 as subprocess
except ImportError:
    import subprocess


@pytest.fixture(scope="function", name="tmpdir")
def fixture_tmpdir():
    with stbt_rig.named_temporary_directory(
            prefix="stbt-rig-selftest-", ignore_errors=True) as d:
        origdir = os.path.abspath(os.curdir)
        try:
            yield d
        finally:
            os.chdir(origdir)


@pytest.fixture(scope="function", name="test_pack")
def fixture_test_pack(tmpdir):  # pylint: disable=unused-argument
    setup_test_pack(tmpdir)
    os.chdir("%s/test-pack" % tmpdir)
    return stbt_rig.TestPack()


def setup_test_pack(tmpdir, portal_url="https://example.stb-tester.com"):
    u = os.path.join(tmpdir, "upstream")

    def tp(path=""):
        return os.path.join(tmpdir, "test-pack", path)

    os.mkdir(u)
    subprocess.check_call(['git', 'init', '--bare'], cwd=u)

    subprocess.check_call(['git', 'clone', 'upstream', 'test-pack'], cwd=tmpdir)

    subprocess.check_call(
        ['git', 'config', 'user.email', 'stbt-rig@stb-tester.com'], cwd=tp())
    subprocess.check_call(
        ['git', 'config', 'user.name', 'stbt-rig tests'], cwd=tp())

    with open(tp(".stbt.conf"), "w") as f:
        f.write(dedent("""\
            [test_pack]
            stbt_version = 32
            python_version = 3
            portal_url = %s
            """ % portal_url))
    with open(tp(".gitignore"), "w") as f:
        f.write("token\n__pycache__\n")
    with open(tp("moo"), 'w') as f:
        f.write("Hello!\n")
    os.mkdir(tp("tests"))
    with open(tp("tests/test.py"), 'w') as f:
        f.write("def test_my_tests():\n    pass\n")
    with open(tp("tests/syntax_error.py"), 'wb') as f:
        f.write(
            b'# codec: utf-8\n\n'
            b'def test_its_a_test():\n\n'
            b'syntax error\n\n'
            b'I am \xf0\x9f\x98\x80')
    shutil.copyfile(_find_file("stbt_rig.py"), tp("stbt_rig.py"))
    os.chmod(tp("stbt_rig.py"), 0o0755)
    subprocess.check_call(
        ['git', 'add', '.stbt.conf', 'moo', '.gitignore', 'stbt_rig.py',
         'tests/syntax_error.py', 'tests/test.py'], cwd=tp())
    subprocess.check_call(['git', 'commit', '-m', 'Test'], cwd=tp())
    subprocess.check_call(
        ['git', 'push', '-u', 'origin', 'master:mybranch'], cwd=tp())


def _find_file(path, root=os.path.dirname(os.path.abspath(__file__))):
    return os.path.join(root, path)

