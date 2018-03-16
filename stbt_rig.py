#!/usr/bin/env python2

"""Command-line tool for interacting with the Stb-tester Portal's REST API.

For more details, and to get the latest version of this script, see
<https://github.com/stb-tester/stbt-rig>.

Copyright 2017 Stb-tester.com Ltd. <support@stb-tester.com>
Released under the MIT license.
"""

import argparse
import ConfigParser
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from textwrap import dedent

# Third-party libraries. Keep this list to a minimum to ease deployment.
import requests


logger = logging.getLogger("stbt_rig")


def main(argv):
    parser = argparse.ArgumentParser(
        description="Command-line tool for interacting with the Stb-tester "
        "Portal's REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
            AUTHENTICATION:
              Go to the Stb-tester Portal in your web browser and create an
              access token. See
              https://stb-tester.com/manual/rest-api-v2#authentication

              When you run this script the first time, you will be prompted to
              type in the access token. If you have the Python "keyring"
              package installed, we will save the token in the secure password
              storage provided by your operating system, so that you don't have
              to type it in again.

              You can also save the access token to a file (don't commit the
              file to the git repository!) and give the filename with
              --portal-auth-file.

              In Jenkins you can use the Credentials Binding plugin to pass the
              access token in an environment variable. See the Jenkins
              documentation below.

            INTERACTIVE MODE:
              In interactive mode (the default mode if not running inside a
              Jenkins job) the "run" command takes a snapshot of your current
              directory and pushes it to the branch YOUR_USERNAME/snapshot on
              GitHub, so that you don't have to make lots of temporary git
              commits to debug your test scripts.

            JENKINS INTEGRATION:
              We automatically detect if we are running inside a Jenkins job.
              If so, we enable the following behaviours:

              * Read the access token from $STBT_AUTH_TOKEN environment
                variable.
              * Record various Jenkins parameters as "tags" in the Stb-tester
                results:
                - jenkins/JOB_NAME
                - jenkins/BUILD_ID
                - jenkins/BUILD_URL
                - jenkins/GIT_COMMIT
                - jenkins/SVN_REVISION
              * Write test results in JUnit format to "stbt-results.xml" for
                the Jenkins JUnit plugin.
              * Stop the tests if you press the "stop" button in Jenkins.

              For instructions on how to configure your Jenkins job see
              https://stb-tester.com/manual/continuous-integration

        """))

    parser.add_argument(
        "-C", metavar="PATH", help="Change to directory PATH before doing "
        "anything else.")

    parser.add_argument(
        "--portal-url", metavar="https://COMPANYNAME.stb-tester.com",
        help="""Base URL of your Stb-tester Portal. You can specify it on the
        command line or as "portal_url" in the [test_pack] section of
        .stbt.conf. We look for .stbt.conf in the current working
        directory.""")

    # Can't pass auth token on command line because it would be visible in
    # /proc. Pass it in a file instead.
    parser.add_argument(
        "--portal-auth-file", metavar="FILENAME",
        help="""File containing the HTTP REST API access token. See the
        AUTHENTICATION section below.""")

    parser.add_argument(
        "--node-id", metavar="stb-tester-abcdef123456",
        help="""Which Stb-tester node to execute the COMMAND on. The node ID is
        labelled on the physical Stb-tester node, and it is also shown in the
        Stb-tester Portal.""")

    parser.add_argument(
        "--git-remote", metavar="NAME", default="origin",
        help="""Which git remote to push to. Defaults to "origin" (this is the
        default name that git creates when you did the original "git clone" of
        the test-pack repository). This is only used by the commands that need
        to push temporary snapshots to git: that is, "run" and "press" when
        "--mode=interactive".""")

    parser.add_argument(
        "--mode", choices=["auto", "interactive", "jenkins"], default="auto",
        help="""See the sections INTERACTIVE MODE and JENKINS INTEGRATION
        below. This defaults to "auto", which detects whether or not it is
        being run inside Jenkins.""")

    parser.add_argument(
        "-v", "--verbose", action="count", dest="verbosity", default=0,
        help="""Specify once to enable INFO logging, twice for DEBUG.""")

    subcommands = parser.add_subparsers(
        dest="command", title="COMMANDS", metavar="COMMAND",
        description=dedent("""\
            Note: Run "./stbt_rig.py COMMAND -h" to see the additional
            parameters for each COMMAND."""))

    run_parser = subcommands.add_parser("run", help="Run test-cases")
    run_parser.add_argument(
        "--force", action="store_true",
        help="""Stop an existing job first (otherwise this script will fail if
        the Stb-tester node is busy)""")
    run_parser.add_argument(
        "--test-pack-revision", metavar="GIT_SHA", help="""Git commit SHA in
        the test-pack repository identifying the version of the tests to run.
        Can also be the name of a git branch or tag. In interactive mode this
        defaults to a snapshot of your current working directory. In jenkins
        mode this defaults to "master".""")
    run_parser.add_argument(
        "--remote-control", metavar="NAME", help="""The remote control infrared
        configuration to use when running the tests. This should match the name
        of a remote control configuration file in your test-pack git
        repository. For example if your test-pack has
        "config/remote-control/roku.lircd.conf" then you should specify "roku".
        If not specified here, you must specify
        "test_pack.default_remote_control" in the test-pack's .stbt.conf""")
    run_parser.add_argument(
        "--category", metavar="NAME", help="""Category to save the test-results
        in. When you are viewing test results you can filter by this string. In
        interactive mode this defaults to "USERNAME/snapshot". In jenkins mode
        this defaults to the Jenkins job name.""")
    run_parser.add_argument(
        "--soak", action="store_true", help="""Run the testcases forever until
        you interrupt them by pressing Control-C.""")
    run_parser.add_argument(
        "--shuffle", action="store_true", help="""Randomise the order in which
        the tests are run. If "--soak" is also specified, this will prefer
        to run the faster test cases more often.""")
    run_parser.add_argument(
        "-t", "--tag", action="append", dest="tags", default=[],
        metavar="NAME=VALUE", help="""Tags are passed to the test scripts in
        sys.argv and are recorded alongside the test-results. "--tag" can be
        specified more than once.""")
    run_parser.add_argument(
        "test_cases", nargs='+', metavar="TESTCASE",
        help="""One or more tests to run. Test names have the form
        FILENAME::FUNCTION_NAME where FILENAME is given relative to the root of
        the test-pack repository and FUNCTION_NAME identifies a Python function
        within that file; for example
        "tests/my_test.py::test_that_blah_dee_blah".""")

    screenshot_parser = subcommands.add_parser(
        "screenshot", help="Save a screenshot to disk")
    screenshot_parser.add_argument(
        "filename", default="screenshot.png", nargs='?',
        help="Output filename. Defaults to %(default)s")

    args = parser.parse_args(argv[1:])

    signal.signal(signal.SIGINT, _exit)
    signal.signal(signal.SIGTERM, _exit)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _exit)  # pylint:disable=no-member

    logging.basicConfig(
        format="%(filename)s: %(levelname)s: %(message)s",
        level=logging.WARNING - args.verbosity * 10)

    if args.C:
        os.chdir(args.C)

    if args.mode == "auto":
        if "JENKINS_HOME" in os.environ:
            args.mode = "jenkins"
        else:
            args.mode = "interactive"

    if not args.portal_url:
        try:
            _, config_parser = read_stbt_conf(os.curdir)
            args.portal_url = config_parser.get('test_pack', 'portal_url')
        except ConfigParser.Error as e:
            die("--portal-url isn't specified on the command line and "
                "test_pack.portal_url isn't specified in .stbt.conf: %s", e)

    if not args.node_id:
        die("argument --node-id is required")

    for portal_auth_token in iter_portal_auth_tokens(
            args.portal_url, args.portal_auth_file, args.mode):

        portal = Portal(args.portal_url, portal_auth_token)
        node = Node(portal, args.node_id)

        try:
            if args.command == "run":
                return cmd_run(args, node)
            elif args.command == "screenshot":
                return cmd_screenshot(args, node)
            assert False, "Unreachable: Unknown command %r" % args.command
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                # Unauthorised. Try again, but with a new password.
                logger.error('Authentication failure with token "...%s"',
                             portal_auth_token[-8:])
            else:
                message = "HTTP %i Error: %s" % (
                    e.response.status_code, e.response.text)
                if hasattr(e, "request"):
                    message += " during %s %s" % (
                        e.request.method, e.request.url)  # pylint:disable=no-member
                die(message)
        except NodeBusyException as e:
            die(str(e))

    # Authentication error and no further tokens
    return 1


def _exit(signo, _):
    name = next(k for k, v in signal.__dict__.iteritems()
                if v == signo and "_" not in k)
    logger.warning("Received %s. Stopping job.", name)
    # Teardown is handled by TestJob.__exit__
    sys.exit(0)


def cmd_run(args, node):
    if args.mode == "interactive":
        response = node.portal._get("/api/v2/user")
        response.raise_for_status()
        username = response.json()["login"]
        branch_name = "%s/snapshot" % username

    if args.test_pack_revision:
        commit_sha = args.test_pack_revision
    else:
        if args.mode == "interactive":
            testpack = TestPack(remote=args.git_remote)
            commit_sha = testpack.push_git_snapshot(branch_name)
        elif args.mode == "jenkins":
            commit_sha = "master"
        else:
            assert False, "Unreachable: Unknown mode %r" % args.mode

    if args.category:
        category = args.category
    else:
        if args.mode == "interactive":
            category = branch_name
        elif args.mode == "jenkins":
            category = os.environ["JOB_NAME"]
        else:
            assert False, "Unreachable: Unknown mode %r" % args.mode

    tags = {}
    if args.mode == "jenkins":
        # Record Jenkins environment variables as tags.
        # GIT_COMMIT or SVN_REVISION will refer to the repo of the STB software
        # being tested in CI, rather than the test-pack repo.
        for v in ["BUILD_ID", "BUILD_URL", "GIT_COMMIT", "JOB_NAME",
                  "SVN_REVISION"]:
            if os.environ.get(v):
                tags["jenkins/%s" % v] = os.environ[v]
    for tag in args.tags:
        try:
            name, value = tag.split("=", 1)
        except ValueError:
            die("Invalid --tag argument: %s (should be NAME=VALUE)" % tag)
        if name in tags:
            die("Duplicate --tag name: %s" % name)
        tags[name] = value

    logger.info("Running tests...")

    job = node.run_tests(
        commit_sha, args.test_cases, args.remote_control, category,
        args.soak, args.shuffle, tags, args.force, await_completion=True)

    results = job.list_results()

    if args.mode == "interactive":
        for result in results:
            print ""
            print result.json["triage_url"]
            result.print_logs()
    elif args.mode == "jenkins":
        # Record results in XML format for the Jenkins JUnit plugin
        results_xml = job.list_results_xml()
        with open("stbt-results.xml", "w") as f:
            f.write(results_xml)

    print "View these test results at: %s/app/#/results?filter=job:%s" % (
        node.portal.url(), job.job_uid)

    if all(result.is_ok() for result in results):
        return 0
    else:
        return 1


def cmd_screenshot(args, node):
    node.save_screenshot(args.filename)
    return 0


def iter_portal_auth_tokens(portal_url, portal_auth_file, mode):
    if portal_auth_file:
        try:
            with open(portal_auth_file) as f:
                yield f.read().strip()
        except IOError as e:
            # NB. str(e) includes the filename
            die("Failed to read portal auth file: %s" % e)
        return

    if mode == "jenkins":
        token = os.environ.get("STBT_AUTH_TOKEN")
        if token:
            yield token
        else:
            die("No access token specified. Use the Jenkins Credentials "
                "Binding plugin to provide the access token in the "
                "environment variable STBT_AUTH_TOKEN")
        return

    assert mode == "interactive", "Unreachable: Unknown mode %s" % mode

    keyring = None
    try:
        import keyring
        out = keyring.get_password(portal_url, "")
        if out:
            yield out
    except ImportError:
        pass

    while True:
        sys.stderr.write('Enter Access Token for portal %s: ' % portal_url)
        token = sys.stdin.readline().strip()
        if token:
            if keyring is not None:
                keyring.set_password(portal_url, "", token)
            else:
                logger.warning(
                    'Failed to save access token in system keyring. '
                    'Install the Python "keyring" package.')
            yield token


def read_stbt_conf(root):
    """
    git for Windows converts symlinks into normal files, but we still need to
    traverse them for the purposes of loading .stbt.conf.
    """
    root = os.path.abspath(root)
    cp = ConfigParser.SafeConfigParser()
    filename = os.path.join(root, '.stbt.conf')
    for _ in range(10):
        try:
            cp.read(filename)
            return os.path.relpath(filename, root), cp
        except ConfigParser.MissingSectionHeaderError:
            if os.name == "posix":
                # POSIX systems can support symlinks so something else must have
                # gone wrong.
                raise
            with open(filename) as f:
                link = f.read()
            filename = os.path.normpath(os.path.join(
                os.path.dirname(filename), link))
            if not filename.startswith(root):
                raise Exception("Traversing .stbt.conf symlinks failed: "
                                "symlink points outside of test-pack")

    raise Exception(
        "Traversing .stbt.conf symlinks failed: Symlink depth too great")


class Result(object):
    def __init__(self, portal, result_json):
        self._portal = portal
        self.json = result_json

    def print_logs(self, stream=None):
        if stream is None:
            stream = sys.stdout
        response = self._portal._get(
            '/api/v2/results%s/stbt.log' % self.json['result_id'])
        response.raise_for_status()
        stream.write(response.content)

    def is_ok(self):
        return self.json['result'] == "pass"


class TestJob(object):
    RUNNING = "running"
    EXITED = "exited"

    def __init__(self, portal, job_uid=None, job_json=None):
        if job_uid is None and job_json is None:
            raise ValueError("TestJob: must specify job_uid or job_json")
        self.portal = portal
        self.job_uid = job_uid or job_json['job_uid']
        if not self.job_uid.startswith('/'):
            raise ValueError("Invalid job uid %r" % self.job_uid)
        self._json = job_json or {}

    def __enter__(self):
        return self

    def __exit__(self, _1, _2, _3):
        self.stop()

    def stop(self):
        if self.get_status() != TestJob.EXITED:
            self._post('/stop').raise_for_status()

    def await_completion(self, timeout=None):
        if timeout is None:
            timeout = 1e9  # 30 years is forever for our purposes
        end_time = time.time() + timeout
        logger.debug("Awaiting completion of job %s", self.job_uid)
        while True:
            if time.time() > end_time:
                raise TimeoutException(
                    "Timeout waiting for job %s to complete" % self.job_uid)
            if self.get_status() != TestJob.RUNNING:
                logger.debug("Job complete %s", self.job_uid)
                return
            try:
                self._get('/await_completion',
                          timeout=min(end_time - time.time(), 60))
            except requests.exceptions.Timeout:
                pass

    def list_results(self):
        r = self.portal._get(
            '/api/v2/results', params={'filter': 'job:%s' % self.job_uid})
        r.raise_for_status()
        return [Result(self.portal, x) for x in r.json()]

    def list_results_xml(self):
        r = self.portal._get(
            '/api/v2/results.xml', params={'filter': 'job:%s' % self.job_uid})
        r.raise_for_status()
        return r.content

    def get_status(self):
        if self._json.get('status') == 'exited':
            # If we were "exited" in the past, then we'll still be "exited" now:
            # Save making another HTTP request
            return TestJob.EXITED
        self._update()
        return self._json['status']

    def _get(self, path="", **kwargs):
        r = self.portal._get(
            '/api/v2/jobs%s%s' % (self.job_uid, path), **kwargs)
        r.raise_for_status()
        return r

    def _post(self, path="", **kwargs):
        r = self.portal._post(
            '/api/v2/jobs%s%s' % (self.job_uid, path), **kwargs)
        r.raise_for_status()
        return r

    def _update(self):
        self._json = self._get().json()


class TimeoutException(RuntimeError):
    pass


class Node(object):
    def __init__(self, portal, node_id):
        self.portal = portal
        self.node_id = node_id

    def run_tests(self, *args, **kwargs):
        return self.portal.run_tests(self.node_id, *args, **kwargs)

    def stop_current_job(self):
        """Safe to call if the job is already stopped."""
        response = self._get('job')
        response.raise_for_status()
        job = TestJob(self.portal, job_json=response.json())
        if job.get_status() == TestJob.RUNNING:
            job.stop()

    def press(self, key, test_pack_revision=None, remote_control=None):
        data = {'key': key}
        if test_pack_revision is not None:
            data['test_pack_revision'] = test_pack_revision
        if remote_control is not None:
            data['remote_control'] = remote_control

        return self._post("press", json=data)

    def save_screenshot(self, filename):
        r = self._get("screenshot.png")
        r.raise_for_status()
        with open(filename, 'w') as f:
            f.write(r.content)

    def _get(self, suffix="", **kwargs):
        return self.portal._get(
            "/api/v2/nodes/%s/%s" % (self.node_id, suffix), **kwargs)

    def _post(self, suffix="", **kwargs):
        return self.portal._post(
            "/api/v2/nodes/%s/%s" % (self.node_id, suffix), **kwargs)


class Portal(object):
    def __init__(self, url, auth_token, readonly=False):
        self._url = url
        self._auth_token = auth_token
        self.readonly = readonly
        self._session = requests.session()

    def url(self, endpoint=""):
        if endpoint.startswith(self._url):
            return endpoint
        else:
            return self._url + endpoint

    def run_tests(
            self, node_id, test_pack_revision, test_cases,
            remote_control=None, category=None, soak=None, shuffle=None,
            tags=None, force=False, timeout=None, await_completion=False):
        if force:
            Node(self, node_id).stop_current_job()

        kwargs = {}
        if remote_control is not None:
            kwargs['remote_control'] = remote_control
        if category is not None:
            kwargs['category'] = category
        if soak:
            kwargs['soak'] = "run forever"
        if shuffle is not None:
            kwargs['shuffle'] = shuffle
        if tags is not None:
            kwargs['tags'] = tags

        kwargs["node_id"] = node_id
        kwargs["test_pack_revision"] = test_pack_revision
        kwargs["test_cases"] = test_cases
        result = self._post('/api/v2/run_tests', json=kwargs)
        if result.status_code == 409:  # 409 CONFLICT
            raise NodeBusyException(
                "Couldn't run test-job on node %s.  Node is currently in use.  "
                "Specify --force to stop current job before running new one" %
                node_id)
        result.raise_for_status()
        job = TestJob(self, job_json=result.json())

        if not await_completion:
            return job

        with job:
            job.await_completion(timeout=timeout)
            return job

    def _get(self, endpoint, headers=None, *args, **kwargs):
        if headers is None:
            headers = {}
        headers["Authorization"] = "token %s" % self._auth_token
        return self._session.get(
            self.url(endpoint), *args, headers=headers, **kwargs)

    def _post(self, endpoint, json=None, headers=None, *args, **kwargs):  # pylint:disable=redefined-outer-name
        from json import dumps
        if headers is None:
            headers = {}
        headers["Authorization"] = "token %s" % self._auth_token
        if self.readonly:
            raise RuntimeError(
                "Not allowed to mutate this TestRunner, please use a different "
                "fixture in your test")
        if json is not None:
            headers['Content-Type'] = 'application/json'
            kwargs['data'] = dumps(json)
        r = self._session.post(
            self.url(endpoint), headers=headers, *args, **kwargs)
        return r


class NodeBusyException(Exception):
    pass


class TestPack(object):
    def __init__(self, root=None, remote="origin"):
        if root is None:
            root = os.curdir
        self.root = root
        self.remote = remote

    def _git(self, cmd, capture_output=True, extra_env=None, **kwargs):
        if capture_output:
            call = subprocess.check_output
        else:
            call = subprocess.check_call

        env = kwargs.get('env', os.environ).copy()
        if extra_env:
            env.update(extra_env)

        logger.debug('+git %s', " ".join(cmd))

        return call(["git"] + cmd, cwd=self.root, env=env, **kwargs)

    def get_sha(self, branch='HEAD', obj_type=None):
        if obj_type:
            branch = "%s^{%s}" % (branch, obj_type)
        return self._git(["rev-parse", '--verify', branch]).strip()

    def take_snapshot(self):
        status = [(x[0:2], x[3:])
                  for x in self._git(['status', '-z']).split('\0')]
        for status_code, filename in status:
            if status_code == '??':
                logging.warning(
                    'Snapshotting git repo: Ignoring untracked file %s.  '
                    'Either add it (with git add) or add it to .gitignore',
                    filename)

        base_commit = self.get_sha(obj_type="commit")

        # state of the working tree
        with named_temporary_directory(prefix="stbt-rig-git-") as tmpdir:
            tmp_index = os.path.join(tmpdir, "index")
            git_dir = self._git(['rev-parse', '--git-dir']).strip()
            shutil.copyfile('%s/index' % git_dir, tmp_index)
            self._git(['add', '-u'],
                      extra_env={'GIT_INDEX_FILE': tmp_index})
            write_tree = self._git(
                ['write-tree'],
                extra_env={'GIT_INDEX_FILE': tmp_index}).strip()

        if self.get_sha(obj_type="tree") == write_tree:
            return base_commit
        else:
            return self._git(
                ['commit-tree', write_tree, '-p', base_commit, '-m',
                 "snapshot"]).strip()

    def push_git_snapshot(self, branch):
        commit_sha = self.take_snapshot()
        options = ['--force']
        if not logger.isEnabledFor(logging.DEBUG):
            options.append('--quiet')
        logger.info("Pushing git snapshot to %s/%s", self.remote, branch)
        self._git(
            ['push'] + options +
            [self.remote,
             '%s:refs/heads/%s' % (commit_sha, branch)])
        return commit_sha


@contextmanager
def named_temporary_directory(suffix='', prefix='tmp', dir=None):
    dirname = tempfile.mkdtemp(suffix, prefix, dir)
    try:
        yield dirname
    finally:
        shutil.rmtree(dirname)


def die(message, *args):
    logger.error(message, *args)
    sys.exit(1)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
