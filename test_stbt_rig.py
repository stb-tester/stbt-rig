from __future__ import (
    absolute_import, division, print_function, unicode_literals)

import logging
import os
import re
import socket
import threading
import time
import subprocess
from contextlib import contextmanager
from sys import executable as python
from textwrap import dedent

import pytest
import requests

import stbt_rig
from stbt_rig import to_unicode


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

    # Make git push a noop
    subprocess.check_call(['git', 'remote', 'add', 'origin', '.'])

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
    return to_unicode(subprocess.check_output(
        ['git', 'cat-file', 'blob', "%s:%s" % (revision, filename)]))


def rev_parse(revision):
    return to_unicode(subprocess.check_output(
        ['git', 'rev-parse', '--verify', revision])).strip()


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


class PortalMock(object):
    def __init__(self):
        import flask
        self.app = flask.Flask(__name__)
        self.expectations = []
        self.thread = None
        self.socket = None

        @self.app.before_request
        def check_auth():
            if (flask.request.headers['Authorization'] !=
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

        @self.app.route('/api/v2/results')
        def get_results():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            return flask.jsonify([{
                "result": "pass",
                "triage_url": ("https://example.stb-tester.com/app/#/result/"
                               "/mynode/6Pfq/167/2018-10-10_13.13.20"),
                "result_id": "/mynode/6Pfq/167/2018-10-10_13.13.20",
              }])

        @self.app.route('/api/v2/results.xml')
        def get_results_xml():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            return PortalMock.RESULTS_XML

        @self.app.route(
            "/api/v2/results/mynode/6Pfq/167/2018-10-10_13.13.20/stbt.log")
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
        'timestamp="2019-06-12T15:26:35">'
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
        https://example.stb-tester.com/app/#/result//mynode/6Pfq/167/2018-10-10_13.13.20
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


def test_run_tests_jenkins(tmpdir, portal_mock):
    env = os.environ.copy()
    env["JENKINS_HOME"] = tmpdir
    env["STBT_AUTH_TOKEN"] = "this is my token"
    env["BUILD_ID"] = "1"
    env["BUILD_URL"] = "https://jenkins/job/test/1"
    env["JOB_NAME"] = "test"
    run_tests_ci(portal_mock, env)


def test_run_tests_bamboo(tmpdir, portal_mock):
    env = os.environ.copy()
    env["bamboo_agentWorkingDirectory"] = tmpdir
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
        env=env)
    assert open("stbt-results.xml").read() == PortalMock.RESULTS_XML
