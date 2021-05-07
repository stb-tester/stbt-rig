import os
import platform
import sys

from conftest import subprocess
from conftest import setup_test_pack


def test_setup(tmpdir, portal_mock):
    if (3, 0) <= sys.version_info < (3, 6):
        from unittest import SkipTest
        raise SkipTest("%s not supported for setup" % sys.version)
    if platform.system() == "Windows" and sys.version_info < (3, 6):
        from unittest import SkipTest
        raise SkipTest("%s not supported for setup" % sys.version)

    import pexpect

    setup_test_pack(tmpdir, portal_url=portal_mock.url)
    test_pack = os.path.join(tmpdir, "test-pack")

    # Undo any venv, we want a seperate venv for the tests and the stbt_rig
    # we're testing
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    venv = env.pop("VIRTUAL_ENV", None)
    if venv and venv in env['PATH']:
        env['PATH'] = os.pathsep.join(
            x for x in env["PATH"].split(os.pathsep) if venv not in x)

    try:
        # Python 3
        stderr = sys.stderr.buffer
    except AttributeError:
        stderr = sys.stderr

    try:
        e = pexpect.spawn("python stbt_rig.py setup", cwd=test_pack,
                          logfile=stderr)
    except AttributeError:
        # Windows:
        from pexpect.popen_spawn import PopenSpawn
        e = PopenSpawn(
            "python stbt_rig.py setup", cwd=test_pack, logfile=stderr)
    e.expect("Enter Access Token for portal %s:" % portal_mock.url,
             timeout=300)
    e.sendline("this is my token")

    e.expect("These nodes are attached to the portal:")
    e.expect("1\\) stb-tester-00044b5af1d3")
    e.expect("2\\) stb-tester-00044b5aff8a")
    e.expect("Which node do you want to use by default?")
    e.sendline("2")
    e.expect(pexpect.EOF, timeout=5)

    # Setup is complete, now lets test that it worked
    env["VIRTUAL_ENV"] = os.path.join(test_pack, ".venv")
    if platform.system() == "Windows":
        env["PATH"] = (
            os.path.join(test_pack, ".venv", "Scripts") + ':' + env["PATH"])
    else:
        env["PATH"] = (
            os.path.join(test_pack, ".venv", "bin") + ':' + env["PATH"])
    with open(os.path.join(test_pack, ".env")) as f:
        env.update(line.split("=", 1) for line in f.read().split('\n') if line)
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="stb-tester-00044b5aff8a")
    subprocess.check_call(
        ["python", "stbt_rig.py", "run", 'tests/test.py::test_my_tests'],
        env=env, cwd=test_pack)


def _find_file(path, root=os.path.dirname(os.path.abspath(__file__))):
    return os.path.join(root, path)
