from __future__ import absolute_import, division, print_function

import glob
import os
import platform
import random
import re
import threading
import time
from contextlib import contextmanager
from sys import executable as python
from textwrap import dedent

import stbt_rig
from stbt_rig import (
    file_lock, named_temporary_directory, to_native_str, to_unicode)
from conftest import (subprocess, PortalMock)

try:
    from queue import Queue
except ImportError:
    from Queue import Queue


def test_testpack_snapshot_no_change_if_no_commits(test_pack):
    with assert_status_unmodified():
        commit_sha, run_sha = test_pack.take_snapshot()
        assert rev_parse("HEAD") == run_sha
        assert tree_sha(commit_sha) == tree_sha(run_sha)
        assert commit_msg(commit_sha) == (
            "snapshot\n\nremoteref: refs/heads/mybranch")

        # Check that the SHA is deterministic:
        time.sleep(1)
        new_commit_sha, new_run_sha = test_pack.take_snapshot()
        assert new_commit_sha == commit_sha
        assert new_run_sha == run_sha


@contextmanager
def assert_status_unmodified():
    pre_status = subprocess.check_output(["git", "status"])
    yield
    post_status = subprocess.check_output(["git", "status"])
    assert pre_status == post_status


def cat(revision, filename):
    return to_unicode(subprocess.check_output(
        ['git', 'cat-file', 'blob', "%s:%s" % (revision, filename)]))


def rev_parse(revision):
    return to_unicode(subprocess.check_output(
        ['git', 'rev-parse', '--verify', revision])).strip()


def tree_sha(revision):
    return to_unicode(subprocess.check_output(
        ['git', 'show', '--format=%T', '--no-patch', revision])).strip()


def commit_msg(revision):
    return to_unicode(subprocess.check_output(
        ['git', 'show', '--format=%s\n\n%b', '--no-patch', revision])).strip()


def test_testpack_snapshot_contains_modifications(test_pack):
    with open("moo", "w") as f:
        f.write("Goodbye!\n")

    with assert_status_unmodified():
        cs, rs = test_pack.take_snapshot()
        assert cs == rs
        assert rs != rev_parse("HEAD")
        assert rev_parse("%s~1" % rs) == rev_parse("HEAD")
        assert cat(rs, 'moo') == "Goodbye!\n"
        assert cat("HEAD", 'moo') == "Hello!\n"


def test_testpack_snapshot_with_untracked_files(test_pack, capsys):
    assert capsys.readouterr() == ("", "")
    with open("other", "w") as f:
        f.write("It's uncommitted\n")

    with assert_status_unmodified():
        orig_sha = rev_parse("HEAD")
        cs, rs = test_pack.take_snapshot()
        # Untracked files aren't included in the snapshot:
        assert orig_sha == rs
        assert tree_sha(cs) == tree_sha(orig_sha)

    assert capsys.readouterr() == ("", dedent("""\
        stbt-rig: Warning: Ignoring untracked files:

            other

        To avoid this warning add untracked files (with "git add") or add them to .gitignore
        """))


def test_run_tests_interactive(capsys, test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")
    assert 0 == stbt_rig.main([
        'stbt_rig.py', '--node-id=mynode', '--portal-url=%s' % portal_mock.url,
        '--portal-auth-file=token', 'run', 'tests/test.py::test_my_tests'])
    expected_stdout = dedent("""\
        https://example.stb-tester.com/app/#/result//mynode/6Pfq/167/2018-10-10T13:13:20
        The log output
        View these test results at: %s/app/#/results?filter=job:/mynode/6Pfq/167
        """) % portal_mock.url
    assert capsys.readouterr().out[-len(expected_stdout):] == expected_stdout

    os.chdir('tests')
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")
    assert 0 == stbt_rig.main([
        'stbt_rig.py', '--node-id=mynode', '--portal-url=%s' % portal_mock.url,
        '--portal-auth-file=../token', 'run', 'test.py::test_my_tests'])
    assert re.match(
        r"stbt-rig/%s \(Python [23]\.\d+\.\d+; (Linux|Windows|Darwin); mode:interactive\)" % stbt_rig_sha(),
        portal_mock.last_user_agent)



def test_run_tests_download_artifacts(test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")

    assert 0 == stbt_rig.main([
        'stbt_rig.py', '--node-id=mynode', '--portal-url=%s' % portal_mock.url,
        '--portal-auth-file=token', 'run',
        '--artifacts=*.png',
        'tests/test.py::test_my_tests'])

    if platform.system() == "Windows":
        path = "mynode\\6Pfq\\167\\2018-10-10T13-13-20\\artifacts\\"
    else:
        path = "mynode/6Pfq/167/2018-10-10T13:13:20/artifacts/"

    assert glob.glob(path + "*") == [path + "screenshot.png"]
    with open(path + "screenshot.png", 'rb') as f:
        assert re.match(b"Downloaded u?'screenshot.png'", f.read())

    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")

    assert 0 == stbt_rig.main([
        'stbt_rig.py', '--node-id=mynode', '--portal-url=%s' % portal_mock.url,
        '--portal-auth-file=token', 'run',
        '--artifacts=*.png', '--artifacts-dest=%s/{filename}' % path,
        'tests/test.py::test_my_tests'])


def test_run_tests_junit_xml(test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")

    assert 0 == stbt_rig.main([
        'stbt_rig.py', '--node-id=mynode', '--portal-url=%s' % portal_mock.url,
        '--portal-auth-file=token', 'run',
        '--junit-xml=results.xml',
        'tests/test.py::test_my_tests'])
    assert open("results.xml").read() == PortalMock.RESULTS_XML


def test_run_tests_pytest(test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")
    env = os.environ.copy()
    env['PYTHONPATH'] = _find_file('.')
    subprocess.check_call([
        python, '-m', 'pytest', '-vv', '-p', 'stbt_rig', '-p', 'no:python',
        '--portal-url=%s' % portal_mock.url, '--portal-auth-file=token',
        '--node-id=mynode', 'tests/test.py::test_my_tests'], env=env)

    os.chdir('tests')
    portal_mock.expect_run_tests(test_cases=['tests/test.py::test_my_tests'],
                                 node_id="mynode")
    subprocess.check_call([
        python, '-m', 'pytest', '-vv', '-p', 'stbt_rig', '-p', 'no:python',
        '--portal-url=%s' % portal_mock.url, '--portal-auth-file=../token',
        '--node-id=mynode', 'test.py::test_my_tests'], env=env)
    assert re.match(
        r"stbt-rig/%s \(Python [23]\.\d+\.\d+; (Linux|Windows|Darwin); mode:pytest\)" % stbt_rig_sha(),
        portal_mock.last_user_agent)


def stbt_rig_sha():
    return to_native_str(subprocess.check_output(
        ["git", "hash-object", _find_file("stbt_rig.py")]).strip()[:7])


def test_run_tests_pytest_unauthorised(test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    env = os.environ.copy()
    env['PYTHONPATH'] = _find_file('.')
    subprocess.check_call([
        "git", "remote", "set-url", "origin",
        "http://%s:%i/unauthorised.git" % portal_mock.address])
    try:
        subprocess.check_output([
            python, '-m', 'pytest', '-vv', '-p', 'stbt_rig', '-p', 'no:python',
            '--portal-url=%s' % portal_mock.url, '--portal-auth-file=token',
            '--node-id=mynode', 'tests/test.py::test_my_tests'], env=env,
            stderr=subprocess.STDOUT)
        assert False, "pytest should have failed with auth error"
    except subprocess.CalledProcessError as e:
        print(e.output)
        assert (
            (b"could not read Username for" in e.output and
             b'terminal prompts disabled' in e.output) or
            b"Authentication failed for" in e.output)
    finally:
        subprocess.check_call(["git", "remote", "set-url", "origin", "."])


def test_collect_tests_pytest(test_pack):
    EXPECTED = (
        b"  StbtRemoteTest('tests/syntax_error.py', 'test_its_a_test', 2)")

    output = subprocess.check_output(
        [python, '-m', 'pytest', '-vv', '-p', 'stbt_rig', '-p', 'no:python',
         '--collect-only'],
        stderr=subprocess.STDOUT)
    print(output)
    assert EXPECTED in output.splitlines()


def test_run_tests_jenkins(tmpdir, portal_mock):
    env = os.environ.copy()
    env["JENKINS_HOME"] = to_native_str(tmpdir)
    env["STBT_AUTH_TOKEN"] = "this is my token"
    env["BUILD_ID"] = "1"
    env["BUILD_URL"] = "https://jenkins/job/test/1"
    env["JOB_NAME"] = "test"
    run_tests_ci(portal_mock, env)


def test_run_tests_bamboo(tmpdir, portal_mock):
    env = os.environ.copy()
    env["bamboo_agentWorkingDirectory"] = to_native_str(tmpdir)
    env["bamboo_STBT_AUTH_PASSWORD"] = "this is my token"
    env["bamboo_shortJobName"] = "test"
    env["bamboo_buildPlanName"] = "test"
    env["bamboo_buildResultKey"] = "1"
    run_tests_ci(portal_mock, env)


def run_tests_ci(portal_mock, env):
    portal_mock.expect_run_tests(test_cases=["tests/test.py::test_my_tests"],
                                 node_id="mynode")
    subprocess.check_call(
        [python, stbt_rig.__file__, "--node-id=mynode",
         "--portal-url", portal_mock.url,
         "run", "tests/test.py::test_my_tests"],
        env=env, timeout=10)
    assert open("stbt-results.xml").read() == PortalMock.RESULTS_XML


def test_file_lock():
    with named_temporary_directory() as d:
        q = Queue()

        def proc():
            n = random.randint(0, 2**31)
            with open("%s/lockfile" % d, "w") as f:
                with file_lock(f.fileno()):
                    q.put(n)
                    time.sleep(0.2)
                    q.put(n)

        for x in range(9):
            threading.Thread(target=proc).start()
        proc()

        for x in range(10):
            # Without locking the numbers would be all jumbled up
            assert q.get() == q.get()


def _find_file(path, root=os.path.dirname(os.path.abspath(__file__))):
    return os.path.join(root, path)
