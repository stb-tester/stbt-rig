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

import pytest
import requests

import stbt_rig
from stbt_rig import to_native_str, to_unicode

try:
    # Needed for timeout argument to wait on Python 2.7
    import subprocess32 as subprocess
except ImportError:
    import subprocess


@pytest.fixture(scope="function", name="tmpdir")
def fixture_tmpdir():
    with stbt_rig.named_temporary_directory(ignore_errors=True) as d:
        origdir = os.path.abspath(os.curdir)
        try:
            os.mkdir("%s/test-pack" % d)
            os.chdir("%s/test-pack" % d)
            yield d
        finally:
            os.chdir(origdir)


@pytest.fixture(scope="function", name="test_pack")
def fixture_test_pack(tmpdir):  # pylint: disable=unused-argument
    os.mkdir("../upstream")
    subprocess.check_call(['git', 'init', '--bare'], cwd="../upstream")

    subprocess.check_call(['git', 'clone', '../upstream', '.'])
    subprocess.check_call([
        'git', 'config', 'user.email', 'stbt-rig@stb-tester.com'])
    subprocess.check_call(['git', 'config', 'user.name', 'stbt-rig tests'])

    with open(".stbt.conf", "w") as f:
        f.write(dedent("""\
            [test_pack]
            portal_url = https://example.stb-tester.com
            """))
    with open(".gitignore", "w") as f:
        f.write("token")
    with open("moo", 'w') as f:
        f.write("Hello!\n")
    os.mkdir("tests")
    with open("tests/test.py", 'w') as f:
        f.write("def test_my_tests():\n    pass\n")
    subprocess.check_call(
        ['git', 'add', '.stbt.conf', 'moo', '.gitignore', 'tests/test.py'])
    subprocess.check_call(['git', 'commit', '-m', 'Test'])
    subprocess.check_call(['git', 'push', '-u', 'origin', 'master:mybranch'])

    return stbt_rig.TestPack()


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


class PortalMock(object):
    def __init__(self):
        import flask
        self.app = flask.Flask(__name__)
        self.expectations = []
        self.thread = None
        self.socket = None

        RESULTS = [{
            "result": "pass",
            "triage_url": ("https://example.stb-tester.com/app/#/result/"
                           "/mynode/6Pfq/167/2018-10-10T13:13:20"),
            "result_id": "/mynode/6Pfq/167/2018-10-10T13:13:20",
            "artifacts": {
                "combined.log": {
                    "size": len(b'Downloaded \'combined.log\''),
                    "md5": "a31802f438fa89d98d77796cadc5be14",
                },
                "screenshot.png": {
                    "size": len(b'Downloaded \'screenshot.png\''),
                    'md5': "4a2ae485dcf5cf9f391cb5ac65128385",
                },
            }
        }]

        @self.app.before_request
        def check_auth():
            if flask.request.path.startswith('/unauthorised.git'):
                # Used for testing git username prompt behaviour
                response = flask.make_response("Unauthorized", 401,
                    {'WWW-Authenticate':'Basic realm="Login Required"'})
                return response
            if (flask.request.headers.get('Authorization') !=
                    "token this is my token"):
                return ("Forbidden", 403)
            else:
                return None

        @self.app.route("/ready")
        def ready():
            return "Ready"

        @self.app.route('/api/v2/user')
        def get_user():
            return flask.jsonify({"login": "tester"})

        @self.app.route('/api/v2/jobs/mynode/6Pfq/167')
        def get_job():
            return flask.jsonify({'status': 'exited'})

        @self.app.route('/api/v2/jobs/mynode/6Pfq/167/await_completion')
        def await_completion():
            return "{}", random.choice([200, 202, 202, 202])

        @self.app.route('/api/v2/results')
        def get_results():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            out = [dict(x) for x in RESULTS]
            for x in out:
                del x['artifacts']
            return flask.jsonify(out)

        @self.app.route('/api/v2/results.xml')
        def get_results_xml():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            assert flask.request.args['include_tz'] == 'true'
            return PortalMock.RESULTS_XML

        @self.app.route('/api/v2/results/<path:result_id>')
        def get_results_details(result_id):
            return flask.jsonify([
                x for x in RESULTS if x['result_id'] == '/' + result_id][0])

        @self.app.route(
                '/api/v2/results/mynode/6Pfq/167/2018-10-10T13:13:20/artifacts'
                '/<path:path>')
        def get_artifact(path):
            return "Downloaded %r" % path, 200

        @self.app.route(
            "/api/v2/results/mynode/6Pfq/167/2018-10-10T13:13:20/stbt.log")
        def get_stbt_log():
            return "The log output\n"

        @self.app.route('/api/v2/run_tests', methods=['POST'])
        def post_run_tests():
            return flask.jsonify(self.on_run_tests(flask.request.json))

        @self.app.route("/shutdown", methods=['POST'])
        def shutdown():
            func = flask.request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return ""

    def __enter__(self):
        from werkzeug.serving import make_server
        from werkzeug.debug import DebuggedApplication

        server = make_server('localhost', 0, DebuggedApplication(self.app))
        self.address = server.socket.getsockname()

        self.thread = threading.Thread(target=server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

        return self

    def __exit__(self, *_):
        requests.post("%s/shutdown" % self.url,
                      headers={'Authorization': "token this is my token"})
        self.thread.join()
        self.thread = None
        self.socket = None

        assert not self.expectations

    @property
    def url(self):
        return "http://%s:%i" % self.address

    def expect_run_tests(self, **kwargs):
        self.expectations.append(kwargs)

    def on_run_tests(self, j):
        expected = self.expectations.pop(0)
        for k, v in expected.items():
            assert j[k] == v
        return {'job_uid': '/mynode/6Pfq/167'}

    RESULTS_XML = (
        '<testsuite disabled="0" errors="0" failures="0" '
        'name="test" skipped="0" tests="1" time="3.270815" '
        'timestamp="2019-06-12T15:26:35+00:00">'
        '<testcase classname="tests/test.py" name="test_my_tests" '
        'time="3.270815"/>'
        '</testsuite>')


@pytest.fixture()
def portal_mock():
    with PortalMock() as m:
        yield m


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
    env['PYTHONPATH'] = os.path.dirname(os.path.abspath(__file__))
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


def test_run_tests_pytest_unauthorised(test_pack, tmpdir, portal_mock):
    with open('token', 'w') as f:
        f.write("this is my token")
    env = os.environ.copy()
    env['PYTHONPATH'] = os.path.dirname(os.path.abspath(__file__))
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
