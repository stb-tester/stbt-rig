#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK

"""Command-line tool for interacting with the Stb-tester Portal's REST API.

For more details, and to get the latest version of this script, see
<https://github.com/stb-tester/stbt-rig>.

Copyright 2017-2020 Stb-tester.com Ltd. <support@stb-tester.com>
Released under the MIT license.
"""

from __future__ import (
    absolute_import, division, print_function, unicode_literals)

import argparse
import errno
import fnmatch
import hashlib
import itertools
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import namedtuple
from contextlib import contextmanager
from textwrap import dedent

# Third-party libraries. Keep this list to a minimum to ease deployment.
import requests

try:
    import configparser
except ImportError:
    # Python 2
    import ConfigParser as configparser

try:
    # Bash tab-completion, if python-argcomplete is installed
    from argcomplete import autocomplete
except ImportError:
    def autocomplete(*_args):
        pass


logger = logging.getLogger("stbt_rig")


def main(argv):
    parser = argparser()
    autocomplete(parser)
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

    resolve_args(args)
    return main_with_args(args)


def resolve_args(args):
    if args.mode == "auto":
        if "JENKINS_HOME" in os.environ:
            args.mode = "jenkins"
        elif "bamboo_agentWorkingDirectory" in os.environ:
            args.mode = "bamboo"
        else:
            args.mode = "interactive"

    if not args.portal_url:
        try:
            _, config_parser = read_stbt_conf(find_test_pack_root())
            args.portal_url = config_parser.get('test_pack', 'portal_url')
        except configparser.Error as e:
            die("--portal-url isn't specified on the command line and "
                "test_pack.portal_url isn't specified in .stbt.conf: %s", e)

    if args.command in ("run", "screenshot") and not args.node_id:
        die("argument --node-id is required")


def main_with_args(args):
    for portal_auth_token in iter_portal_auth_tokens(
            args.portal_url, args.portal_auth_file, args.mode):

        portal = Portal(args.portal_url, portal_auth_token)
        node = Node(portal, args.node_id)

        try:
            if args.command == "run":
                return cmd_run(args, node)
            elif args.command == "screenshot":
                return cmd_screenshot(args, node)
            elif args.command == "snapshot":
                return cmd_snapshot(args, node)
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


class Arg(namedtuple(
        'Arg', 'name action nargs default choices help metavar dest '
        'completer cmdline_only')):
    def add(self, parser):
        d = {k: v for k, v in self._asdict().items()
             if (k not in ['name', 'completer', 'cmdline_only'] and
                 v is not None)}
        a = parser.add_argument(
            *(self[0] if isinstance(self[0], tuple) else (self[0],)),
            **d)
        if self.completer:
            a.completer = self.completer

    @property
    def longname(self):
        if isinstance(self.name, tuple):
            return self.name[1]
        else:
            return self.name

Arg.__new__.__defaults__ = (
    None, None, None, None, None, None, None, None, False)


def _list_node_ids(**_kwargs):
    """Used for command-line tab-completion.

    For lack of a better place too look, looks for configuration files in
    config/test-farm -- see https://stb-tester.com/manual/advanced-configuration#node-specific-configuration-files
    """

    return [f[17:-5]
            for f in to_unicode(subprocess.check_output(
                ["git", "ls-files", "config/test-farm/stb-tester-*.conf"]))
            .strip().split("\n")]


def _list_test_cases(prefix, **_kwargs):
    """Used for command-line tab-completion."""

    if "::" in prefix:
        # List testcases in the file.
        filename = prefix.split("::")[0]
        tests = []
        for line in open(filename):
            m = re.match(r"^def\s+(test_[a-zA-Z0-9_]+)", line)
            if m:
                tests.append(filename + "::" + m.group(1))
        return tests

    else:
        # List files:
        return [f + "::"
                for f in to_unicode(subprocess.check_output(
                    ["git", "ls-files", "tests/**.py"])).strip().split("\n")]


ARGPARSE_EPILOGUE = dedent("""\
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
      directory and pushes it to the branch "YOUR_USERNAME/snapshot" on
      GitHub, so that you don't have to make lots of temporary git
      commits to debug your test scripts.

    JENKINS INTEGRATION:
      We automatically detect if we are running inside a Jenkins job.
      If so, we enable the following behaviours:

      * Read the access token from $STBT_AUTH_TOKEN environment
        variable.
      * Record various Jenkins parameters as "tags" in the Stb-tester
        results:
        - jenkins/BUILD_ID
        - jenkins/BUILD_URL
        - jenkins/GIT_COMMIT
        - jenkins/JOB_NAME
        - jenkins/SVN_REVISION
      * Write test results in JUnit format to "stbt-results.xml" for
        the Jenkins JUnit plugin.
      * Stop the tests if you press the "stop" button in Jenkins.

      For instructions on how to configure your Jenkins job see
      https://stb-tester.com/manual/continuous-integration

    BAMBOO INTEGRATION:
      Similarly, we automatically detect if we are running from
      Bamboo (Atlassian's continuous integration server):

      * Read the access token from bamboo.STBT_AUTH_PASSWORD variable.
      * Record the following Bamboo variables as "tags" in the
        Stb-tester results:
        - bamboo.buildPlanName
        - bamboo.buildResultKey
        - bamboo.buildResultsUrl
        - bamboo.planRepository.branchName
        - bamboo.planRepository.revision
      * Write test results in JUnit format to "stbt-results.xml"
        suitable for Bamboo's "JUnit Parser" task.
      * Stop the tests if you press "Stop build" in Bamboo.

      For instructions on how to configure your Bamboo job see
      https://stb-tester.com/manual/continuous-integration
""")

ARGS = [
    Arg("-C", metavar="PATH", help="Change to directory PATH before doing "
        "anything else.", cmdline_only=True),

    Arg("--portal-url", metavar="https://COMPANYNAME.stb-tester.com",
        help="""Base URL of your Stb-tester Portal. You can specify it on the
        command line or as "portal_url" in the [test_pack] section of
        .stbt.conf. We look for .stbt.conf in the current working
        directory."""),

    # Can't pass auth token on command line because it would be visible in
    # /proc. Pass it in a file instead.
    Arg("--portal-auth-file", metavar="FILENAME",
        help="""File containing the HTTP REST API access token. See the
        AUTHENTICATION section below."""),

    Arg("--node-id", metavar="stb-tester-abcdef123456",
        help="""Which Stb-tester node to execute the COMMAND on. The node ID is
        labelled on the physical Stb-tester node, and it is also shown in the
        Stb-tester Portal.""", completer=_list_node_ids),

    Arg("--git-remote", metavar="NAME", default="origin",
        help="""Which git remote to push to. Defaults to "origin" (this is the
        default name that git creates when you did the original "git clone" of
        the test-pack repository). This is only used by the commands that need
        to push temporary snapshots to git: that is, "run" and "press" when
        "--mode=interactive"."""),

    Arg("--mode", choices=["auto", "bamboo", "interactive", "jenkins"],
        default="auto",
        help="""See the sections INTERACTIVE MODE and JENKINS INTEGRATION
        below. This defaults to "auto", which detects whether or not it is
        being run inside Jenkins or Bamboo.""", cmdline_only=True),

    Arg("--csv", metavar="FILENAME",
        help="Also write test-results in CSV format to the specified file."),

    Arg(("-v", "--verbose"), action="count", dest="verbosity", default=0,
        help="""Specify once to enable INFO logging, twice for DEBUG.""",
        cmdline_only=True),
]

RUN_ARGS = [
    Arg("--force", action="store_true",
        help="""Stop an existing job first (otherwise this script will fail if
        the Stb-tester node is busy)."""),

    Arg("--test-pack-revision", metavar="GIT_SHA", help="""Git commit SHA in
        the test-pack repository identifying the version of the tests to run.
        Can also be the name of a git branch or tag. In interactive mode this
        defaults to a snapshot of your current working directory. In jenkins
        mode this defaults to "master"."""),

    Arg("--remote-control", metavar="NAME", help="""The remote control infrared
        configuration to use when running the tests. This should match the name
        of a remote control configuration file in your test-pack git
        repository. For example if your test-pack has
        "config/remote-control/roku.lircd.conf" then you should specify "roku".
        If not specified here, you must specify
        "test_pack.default_remote_control" in the test-pack's .stbt.conf"""),

    Arg("--category", metavar="NAME", help="""Category to save the test-results
        in. When you are viewing test results you can filter by this string. In
        interactive mode this defaults to "USERNAME/snapshot". In jenkins mode
        this defaults to the Jenkins job name."""),

    Arg("--soak", action="store_true", help="""Run the testcases forever until
        you interrupt them by pressing Control-C.""", cmdline_only=True),

    Arg("--shuffle", action="store_true", help="""Randomise the order in which
        the tests are run. If "--soak" is also specified, this will prefer
        to run the faster testcases more often.""", cmdline_only=True),

    Arg(("-t", "--tag"), action="append", dest="tags", default=[],
        metavar="NAME=VALUE", help="""Tags are passed to the test scripts in
        sys.argv and are recorded alongside the test-results. "--tag" can be
        specified more than once."""),

    Arg(("--artifacts"), action="append", dest="artifacts", default=[],
        metavar="GLOB", help="""Select artifacts to be downloaded.  This is a
        filename glob.  Set to `*` for all artifacts.  This argument can be
        specified multiple times."""),

    Arg(("--artifacts-dest"), default=None, metavar="PATH", help="""Artifacts
        will be downloaded to here.  You can include the placeholders
        {result_id}, {filename} and {basename} here to be filled in
        automatically by stbt_rig.  Defaults to
        {result_id}/artifacts/{filename}.  Directories will be created as
        required."""),

    Arg("--junit-xml", action="append", dest="junit_xml", default=[],
        help="""Save JUnit style XML file with results to this path.  This is
        enabled by default in jenkins or bamboo mode.""", cmdline_only=True),

    Arg("test_cases", nargs='+', metavar="TESTCASE",
        help="""One or more tests to run. Test names have the form
        FILENAME::FUNCTION_NAME where FILENAME is given relative to the root of
        the test-pack repository and FUNCTION_NAME identifies a Python function
        within that file; for example
        "tests/my_test.py::test_that_blah_dee_blah".""", cmdline_only=True,
        completer=_list_test_cases)
]


def argparser():
    parser = argparse.ArgumentParser(
        description="Command-line tool for interacting with the Stb-tester "
        "Portal's REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=ARGPARSE_EPILOGUE)

    for arg in ARGS:
        arg.add(parser)

    subcommands = parser.add_subparsers(
        dest="command", title="COMMANDS", metavar="COMMAND",
        description=dedent("""\
            Note: Run "./stbt_rig.py COMMAND -h" to see the additional
            parameters for each COMMAND."""))

    run_parser = subcommands.add_parser(
        "run", help="Run testcases",
        description="""Run the specified testcases on the specified Stb-tester
        node. In interactive mode (the default mode if not running inside a
        Jenkins job) it also pushes a snapshot of your current test-pack and
        pushes it to the branch YOUR_USERNAME/snapshot on GitHub, so that you
        don't have to make lots of temporary git commits to debug your test
        scripts.""")

    for arg in RUN_ARGS:
        arg.add(run_parser)

    screenshot_parser = subcommands.add_parser(
        "screenshot", help="Save a screenshot to disk",
        description="""Take a screenshot from the specified Stb-tester node
        and save it to disk.""")
    screenshot_parser.add_argument(
        "filename", default="screenshot.png", nargs='?',
        help="""Output filename. Defaults to "%(default)s".""")

    subcommands.add_parser(
        "snapshot", help="Push a snapshot of your current test-pack",
        description="""Take a snapshot of your current test-pack and push it
        to the branch "YOUR_USERNAME/snapshot" on GitHub. Note that the "run"
        command automatically does this when in interactive mode.""")

    return parser


def _exit(signo, _):
    name = next(k for k, v in signal.__dict__.items()
                if v == signo and "_" not in k)
    logger.warning("Received %s. Stopping job.", name)
    # Teardown is handled by TestJob.__exit__
    sys.exit(0)


def cmd_run(args, node):
    j = cmd_run_prep(args, node.portal)
    return cmd_run_body(args, node, j)


JobPrepResult = namedtuple("JobPrepResult", "commit_sha category tags")


def cmd_run_prep(args, portal):
    if args.mode in ["interactive", "pytest"]:
        branch_name = _get_snapshot_branch_name(portal)

    if args.test_pack_revision:
        commit_sha = args.test_pack_revision
    else:
        if args.mode == "interactive":
            commit_sha = TestPack(remote=args.git_remote) \
                         .push_git_snapshot(branch_name)
        elif args.mode == "pytest":
            commit_sha = TestPack(remote=args.git_remote) \
                         .push_git_snapshot(branch_name, interactive=False)
        elif args.mode in ["bamboo", "jenkins"]:
            # We assume that when in CI we're not in the git repo of the
            # test-pack, so run tests from master.
            commit_sha = "master"
        else:
            assert False, "Unreachable: Unknown mode %r" % args.mode

    if args.category:
        category = args.category
    else:
        if args.mode in ["interactive", "pytest"]:
            category = branch_name
        elif args.mode == "jenkins":
            category = os.environ["JOB_NAME"]
        elif args.mode == "bamboo":
            category = os.environ["bamboo_shortJobName"]
        else:
            assert False, "Unreachable: Unknown mode %r" % args.mode

    tags = {}
    if args.mode == "jenkins":
        # Record Jenkins environment variables as Stb-tester tags.
        # GIT_COMMIT or SVN_REVISION will refer to the repo of the STB software
        # being tested in CI, rather than the test-pack repo.
        for v in ["BUILD_ID", "BUILD_URL", "GIT_COMMIT", "JOB_NAME",
                  "SVN_REVISION"]:
            if os.environ.get(v):
                tags["jenkins/%s" % v] = os.environ[v]
    elif args.mode == "bamboo":
        # Record Bamboo variables as Stb-tester tags. Bamboo exports its
        # variables as environment variables with dots replaced by underscores.
        # "bamboo.planRepository.revision" will refer to the repo of the STB
        # software being tested in CI, rather than the test-pack repo.
        # See the complete list of bamboo variables here:
        # https://confluence.atlassian.com/bamboo/bamboo-variables-289277087.html
        for v in ["bamboo.buildPlanName",
                  "bamboo.buildResultKey",
                  "bamboo.buildResultsUrl",
                  "bamboo.planRepository.branchName",
                  "bamboo.planRepository.revision"]:
            value = os.environ.get(v.replace(".", "_"))
            if value:
                tags[v] = value
    for tag in args.tags:
        try:
            name, value = tag.split("=", 1)
        except ValueError:
            die("Invalid --tag argument: %s (should be NAME=VALUE)" % tag)
        if name in tags:
            die("Duplicate --tag name: %s" % name)
        tags[name] = value

    return JobPrepResult(commit_sha, category, tags)


def cmd_run_body(args, node, j):
    logger.info("Running tests...")

    try:
        root = find_test_pack_root()
        test_cases = [os.path.relpath(x, root).replace('\\', '/')
                      for x in args.test_cases]
    except NotInTestPack:
        test_cases = args.test_cases

    job = node.run_tests(
        j.commit_sha, test_cases, args.remote_control, j.category,
        args.soak, args.shuffle, j.tags, args.force)

    try:
        job.await_completion()
    except SystemExit:  # raised by our signal handler
        job.stop()

    results = job.list_results()

    if args.mode in ["interactive", 'pytest']:
        for result in results:
            print("")
            print(result.json["triage_url"])
            result.print_logs()
    elif args.mode in ["bamboo", "jenkins"]:
        # Record results in XML format for the Jenkins JUnit plugin
        if not args.junit_xml:
            args.junit_xml = ["stbt-results.xml"]

    if args.junit_xml:
        results_xml = job.list_results_xml()
        for filename in args.junit_xml:
            with open(filename, "w") as f:
                f.write(results_xml)

    if args.csv:
        results_csv = job.list_results_csv()
        with open(args.csv, "w") as f:
            f.write(results_csv)

    if args.artifacts:
        logger.info("Downloading artifacts...")
        for result in results:
            result.download_artifacts(args.artifacts, args.artifacts_dest)

    print("View these test results at: %s/app/#/results?filter=job:%s" % (
        node.portal.url(), job.job_uid))

    if args.mode == "pytest":
        for result in results:
            result.raise_for_result()
        return 0
    else:
        if all(result.is_ok() for result in results):
            return 0
        else:
            return 1


def cmd_screenshot(args, node):
    node.save_screenshot(args.filename)
    return 0


def cmd_snapshot(args, node):
    branch_name = _get_snapshot_branch_name(node.portal)
    TestPack(remote=args.git_remote).push_git_snapshot(branch_name)
    node.portal.notify_push()


def _get_snapshot_branch_name(portal):
    response = portal._get("/api/v2/user")
    response.raise_for_status()
    username = response.json()["login"]
    return "refs/snapshots/%s" % username


class NotInTestPack(Exception):
    pass


def find_test_pack_root():
    """Walks upward from the current directory until it finds a directory
    containing .stbt.conf
    """
    root = os.getcwd()

    # This gets the toplevel in a cross-platform manner "/" on UNIX and
    # (typically) "c:\" on Windows:
    toplevel = os.path.abspath(os.sep)

    while root != toplevel:
        if os.path.exists(os.path.join(root, '.stbt.conf')):
            return root
        root = os.path.split(root)[0]
    raise NotInTestPack(
        """Didn't find ".stbt.conf" at the root of your test-pack """
        """(starting at %s)""" % os.getcwd())


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

    if mode == "bamboo":
        token = os.environ.get("bamboo_STBT_AUTH_PASSWORD")
        if token:
            yield token
        else:
            die("No access token specified. Provide the access token in the "
                "variable bamboo.STBT_AUTH_PASSWORD")
        return

    assert mode in ["interactive", "pytest"], \
        "Unreachable: Unknown mode %s" % mode

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
        sys.stderr.flush()
        token = sys.stdin.readline()
        if not token:
            # EOF
            sys.stderr.write("EOF!\n")
            sys.stderr.flush()
            break
        token = token.strip()
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
    cp = configparser.SafeConfigParser()
    filename = os.path.join(root, '.stbt.conf')
    for _ in range(10):
        try:
            cp.read(filename)
            return os.path.relpath(filename, root), cp
        except configparser.MissingSectionHeaderError:
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


class TestFailure(AssertionError):
    result = 'fail'


class TestError(Exception):
    result = 'error'


class Result(object):
    def __init__(self, portal, result_json):
        self._portal = portal
        self.json = result_json

    @property
    def result_id(self):
        return self.json['result_id']

    def print_logs(self, stream=None):
        if stream is None:
            stream = sys.stdout
        tz = _get_local_timezone()
        if tz:
            params = {"tz": tz}
        else:
            params = {}
        response = self._portal._get(
            '/api/v2/results%s/stbt.log' % self.result_id,
            params=params)
        response.raise_for_status()
        stream.write(response.text)

    def list_artifacts(self):
        if 'artifacts' not in self.json:
            r = self._portal._get("/api/v2/results%s" % self.result_id)
            r.raise_for_status()
            self.json = r.json()
        return self.json["artifacts"]

    def download_artifacts(self, patterns=("*",), out_pattern=None):
        if out_pattern is None:
            if platform.system() == "Windows":
                out_pattern = "{result_id}\\artifacts\\{filename}"
            else:
                out_pattern = "{result_id}/artifacts/{filename}"
        for filename, info in self.list_artifacts().items():
            for p in patterns:
                if fnmatch.fnmatch(filename, p):
                    break
            else:
                continue

            native_filename = filename.replace('/', os.sep)

            format_kwargs = {
                "basename": os.path.basename(native_filename),
                "filename": native_filename,
            }

            for k, v in self.json.items():
                if isinstance(v, unicode):
                    # Strip the leading '/' from result_id so we don't write
                    # files to root
                    v = v.strip('/')

                    # Support Windows path separator:
                    v = v.replace('/', os.sep)

                    # Windows can't support : in filenames, so replace the : in
                    # the ISO8601 date:
                    if platform.system() == "Windows":
                        v = v.replace(":", "-")

                    format_kwargs[k] = v

            outname = out_pattern.format(**format_kwargs)
            self.download_artifact(filename, outname, info)

    def download_artifact(self, artifact, outname, info=None):
        # This way we can avoid downloading the same file twice if we've already
        # downloaded it:
        if info and _file_is_same(outname, info['size'], info['md5']):
            logger.debug("Not Downloading %s/artifacts/%s to %s - file is "
                         "unmodified", self.result_id, artifact, outname)
            return

        logger.debug("Downloading %s/artifacts/%s to %s",
                     self.result_id, artifact, outname)
        resp = self._portal._get(
            "/api/v2/results%s/artifacts/%s" % (self.result_id, artifact),
            stream=True)
        resp.raise_for_status()
        mkdir_p(os.path.dirname(outname))
        with sponge(outname) as f:
            for x in resp.iter_content(chunk_size=None):
                f.write(x)

    def is_ok(self):
        return self.json['result'] == "pass"

    def raise_for_result(self):
        if self.json['result'] == 'pass':
            return

        if 'traceback' not in self.json:
            response = self._portal._get(
                '/api/v2/results%s' % self.json['result_id'])
            response.raise_for_status()
            self.json = response.json()

        if self.json['result'] == 'error':
            raise TestError(self.json['traceback'])
        elif self.json['result'] == 'fail':
            raise TestFailure(self.json['traceback'])


def _get_local_timezone():
    try:
        import tzlocal
        return str(tzlocal.get_localzone())
    except ImportError:
        pass
    if platform.system() != "Windows":
        try:
            # On Unix systems /etc/localtime is a symlink. On Ubuntu it points
            # to "/usr/share/zoneinfo/Europe/London". On MacOS it points to
            # "/var/db/timezone/zoneinfo/Europe/London".
            zoneinfo_filename = os.readlink("/etc/localtime")  # pylint:disable=no-member
            m = re.match(r"^.*/zoneinfo/(.*)", zoneinfo_filename)
            if m:
                return m.group(1)
        except OSError:
            pass
    return None


def _file_is_same(filename, size, md5sum):
    try:
        if os.stat(filename).st_size != size:
            return False
        with open(filename, "rb") as f:
            h = hashlib.md5()
            while True:
                x = f.read(1024 * 1024)
                if not x:
                    break
                h.update(x)
            return h.hexdigest() == md5sum
    except OSError:
        return False


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

    def stop(self, timeout=600):
        if self.get_status() != TestJob.EXITED:
            # Sometimes jobs take a long time to stop (uploading artifacts);
            # in that case we get 202 Accepted after 55s to avoid other HTTP
            # server or client timeouts.
            # The "<job_id>/stop" endpoint is idempotent so it's safe to retry.
            self._post('/stop', timeout=timeout, retry=True).raise_for_status()

    def await_completion(self, timeout=None):
        logger.debug("Awaiting completion of job %s", self.job_uid)
        try:
            response = self._get(
                '/await_completion', retry=True, timeout=timeout)
            response.raise_for_status()
            logger.debug("Job complete %s", self.job_uid)
        except requests.exceptions.Timeout:
            raise TimeoutException(
                "Timeout waiting for job %s to complete" % self.job_uid)

    def list_results(self):
        r = self.portal._get(
            '/api/v2/results', params={'filter': 'job:%s' % self.job_uid})
        r.raise_for_status()
        return [Result(self.portal, x) for x in r.json()]

    def list_results_xml(self):
        r = self.portal._get(
            '/api/v2/results.xml', params={'filter': 'job:%s' % self.job_uid,
                                           'include_tz': 'true'})
        r.raise_for_status()
        return r.text

    def list_results_csv(self):
        r = self.portal._get(
            '/api/v2/results.csv', params={'filter': 'job:%s' % self.job_uid})
        r.raise_for_status()
        return r.text

    def get_status(self, timeout=60):
        if self._json.get('status') == 'exited':
            # If we were "exited" in the past, then we'll still be "exited" now:
            # Save making another HTTP request
            return TestJob.EXITED
        self._json = self._get(timeout=timeout).json()
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
        with open(filename, 'wb') as f:
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
        self.readonly = readonly

        session = requests.session()
        session.headers.update({
            "Authorization": "token %s" % auth_token,
            "User-Agent": "stbt-rig"})
        self._session = RetrySession(
            timeout=1e9, session=session, logger=logger)

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

    def notify_push(self):
        self._post("/github/post-receive").raise_for_status()

    def _get(self, endpoint, timeout=60, **kwargs):
        return self._session.get(self.url(endpoint), timeout=timeout, **kwargs)

    def _post(self, endpoint, json=None, headers=None, timeout=60, **kwargs):  # pylint:disable=redefined-outer-name
        from json import dumps
        if headers is None:
            headers = {}
        if self.readonly:
            raise RuntimeError(
                "Not allowed to mutate this TestRunner, please use a different "
                "fixture in your test")
        if json is not None:
            headers['Content-Type'] = 'application/json'
            kwargs['data'] = dumps(json)
        r = self._session.post(
            self.url(endpoint), headers=headers, timeout=timeout, **kwargs)
        return r


class NodeBusyException(Exception):
    pass


class TestPack(object):
    def __init__(self, root=None, remote="origin"):
        if root is None:
            root = find_test_pack_root()
        self.root = root
        self.remote = remote

    @staticmethod
    def _git(cmd, extra_env=None, interactive=False, **kwargs):
        env = kwargs.get('env', os.environ).copy()
        if extra_env:
            env.update(extra_env)
        if not interactive:
            if 'stdin' not in kwargs:
                kwargs["stdin"] = open(os.devnull, "r")
            env['GIT_TERMINAL_PROMPT'] = b'0'

        # On Windows environment variables must be bytes on 2.7 and unicode on
        # 3.0+
        env = {to_native_str(k): to_native_str(v) for k, v in env.items()}

        logger.debug('+git %s', " ".join(cmd))

        return to_unicode(
            subprocess.check_output(["git"] + cmd, env=env, **kwargs))

    def get_sha(self, branch='HEAD', obj_type=None):
        if obj_type:
            branch = "%s^{%s}" % (branch, obj_type)
        return self._git(["rev-parse", '--verify', branch]).strip()

    def take_snapshot(self):
        status = [(x[0:2], x[3:])
                  for x in self._git(['status', '-z']).split('\0')]
        untracked_files = [filename for status_code, filename in status
                           if status_code == "??"]
        if untracked_files:
            sys.stderr.write("stbt-rig: Warning: Ignoring untracked files:\n\n")
            for filename in untracked_files:
                sys.stderr.write("    %s\n" % filename)
            sys.stderr.write(
                '\nTo avoid this warning add untracked files (with "git add") '
                'or add them to .gitignore\n')
            sys.stderr.flush()

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

        head = self._git(["rev-parse", "--symbolic-full-name", "HEAD"]).strip()
        remoteref = self._git(
            ["for-each-ref",
             "--format=%(push:remoteref)\n%(upstream:remoteref)\n",
             head]).split('\n')
        if remoteref and remoteref[0]:
            # push:remoteref set if the repo is configured to push to a
            # different place from which it fetches
            remoteref = remoteref[0]
        elif len(remoteref) > 1 and remoteref[1]:
            # upstream:remoteref will be set otherwise, assuming we've actually
            # got a remote tracking branch.
            remoteref = remoteref[1]
        else:
            remoteref = ""

        no_workingdir_changes = (self.get_sha(obj_type="tree") == write_tree)
        if no_workingdir_changes:
            # No changes, we still want a new commit so we can inform the portal
            # which branch we're working on.  We copy over the author date and
            # committer date so we'll get the same SHA every time.  This will
            # cut down on push time and object pollution.
            ad, cd = self._git(
                ["show", base_commit, "--no-patch",
                 "--format=%ad\n%cd"]).split('\n')[:2]
            extra_env = {"GIT_AUTHOR_DATE": ad, "GIT_COMMITTER_DATE": cd}
        else:
            extra_env = {}

        commit_sha = self._git(
            ['commit-tree', write_tree, '-p', base_commit, '-m',
             "snapshot\n\nremoteref: %s" % remoteref],
            extra_env=extra_env).strip()

        if no_workingdir_changes:
            return commit_sha, base_commit
        else:
            return commit_sha, commit_sha

    def push_git_snapshot(self, branch, interactive=True):
        commit_sha, run_sha = self.take_snapshot()
        options = ['--force']
        if not logger.isEnabledFor(logging.DEBUG):
            options.append('--quiet')
        logger.info("Pushing git snapshot %s to %s:%s",
                    commit_sha[:7], self.remote, branch)
        self._git(
            ['push'] + options +
            [self.remote,
             '%s:%s' % (commit_sha, branch)],
            interactive=interactive)
        return run_sha


class RetrySession(object):
    """
    Emulates a requests session but with retry and timeout logic for a sequence
    of HTTP requests.
    """
    def __init__(self, timeout, session=None, interval=1,
                 logger=logging.getLogger('retry_session'),  # pylint: disable=redefined-outer-name
                 _time=None):
        if session is None:
            session = requests.Session()
        if _time is None:
            _time = time

        self._time = _time
        self._session = session
        self._end_time = self._time.time() + timeout
        self._interval = interval
        self._logger = logger

    def put(self, url, data=None, **kwargs):
        return self.request('put', url, data=data, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request('post', url, data=data, json=json, **kwargs)

    def get(self, url, params=None, **kwargs):
        kwargs.setdefault('allow_redirects', True)
        return self.request('get', url, params=params, **kwargs)

    def request(self, method, url, timeout=None, retry=None, **kwargs):
        last_exc_info = (None, None, None)
        if timeout is not None:
            end_time = self._time.time() + timeout
        else:
            end_time = self._end_time
        if retry is None:
            # GET and PUT are idempotent
            retry = method.lower() in ['get', 'put']
        if not retry:
            return self._session.request(method, url, timeout=timeout, **kwargs)

        # We'll double interval below:
        interval = self._interval / 2.
        while True:
            now = self._time.time()
            if now >= end_time:
                self._logger.warning(
                    "Timed out making request %s %s", method, url,
                    exc_info=last_exc_info)
                if last_exc_info[0] is not None:
                    raise_(last_exc_info[0], last_exc_info[1], last_exc_info[2])
                else:
                    raise RetryTimeout()

            # We have a global timeout: we don't want any single request to
            # take longer than 1/2 of the time remaining to allow for retries.
            #
            # We also place a limit of 60s.  Requests to the portal should
            # time-out in less time than this anyway.  The risk of a longer
            # timeout is that the connection gets dropped silently by a some
            # middlebox and we wait for ages when we're never going to get a
            # response.
            timeout = min(60, max((end_time - now) / 2, 1))
            kwargs.setdefault('timeout', timeout)
            response = None
            try:
                response = self._session.request(method, url, **kwargs)
                if response.status_code == 202:
                    # We return 202 "Accepted" from our endpoints indicating
                    # that we've started the requested operation, but haven't
                    # finished yet.  Typically this is used for long-poll.  It's
                    # the equivalent to a syscall returning EAGAIN.
                    pass
                elif response.status_code < 500:
                    # Avoid traceback circular references:
                    del last_exc_info
                    # Success or 4xx client error: don't retry
                    return response
                else:
                    response.raise_for_status()
            except requests.RequestException as e:
                # Exponential backoff up to 30s
                interval = max(
                    self._interval,
                    min(interval * 2, 30, end_time - time.time() - 1))
                self._logger.info(
                    "request %s %s failed.  Will retry in %is", method, url,
                    interval, exc_info=True)
                if e.response:
                    self._logger.info('Got response %r', e.response.text)
                last_exc_info = sys.exc_info()
                self._time.sleep(interval)


class RetryTimeout(requests.exceptions.Timeout):
    pass


try:
    import pytest

    def pytest_addoption(parser):
        group = parser.getgroup("stbt", "stb-tester REST API")
        for arg in itertools.chain(ARGS, RUN_ARGS):
            if arg.cmdline_only:
                continue
            d = {k: v for k, v in arg._asdict().items()
                 if (k not in ['name', 'completer', 'cmdline_only'] and
                     v is not None)}
            group.addoption(arg.longname, **d)


    def pytest_collect_file(path, parent):
        if path.ext == ".py":
            if hasattr(StbtCollector, "from_parent"):
                # pytest >v5.4
                return StbtCollector.from_parent(parent=parent, fspath=path)  # pylint:disable=no-member
            else:
                # Backwards compat
                # https://docs.pytest.org/en/stable/deprecations.html#node-construction-changed-to-node-from-parent
                return StbtCollector(path, parent)
        else:
            return None


    class StbtCollector(pytest.File):
        # pylint: disable=abstract-method
        def collect(self):
            with open(self.fspath.strpath) as f:
                # We implement our own parsing to avoid import stbt ImportErrors
                for n, line in enumerate(f):
                    m = re.match(r'^def\s+(test_[a-zA-Z0-9_]*)', line)
                    if m:
                        if hasattr(StbtRemoteTest, "from_parent"):
                            # pytest >v5.4
                            srt = StbtRemoteTest.from_parent(  # pylint:disable=no-member
                                parent=self, filename=self.name,
                                testname=m.group(1), line_number=n + 1)
                        else:
                            # Backwards compat
                            # https://docs.pytest.org/en/stable/deprecations.html#node-construction-changed-to-node-from-parent
                            srt = StbtRemoteTest(
                                self, self.name, m.group(1), n + 1)
                        yield srt


    class StbtRemoteTest(pytest.Item):
        # pylint: disable=abstract-method
        def __init__(self, parent, filename, testname, line_number):
            super(StbtRemoteTest, self).__init__(testname, parent)
            self._filename = filename
            self._testname = testname
            self._line_number = line_number

        def __repr__(self):
            return "StbtRemoteTest(%r, %r, %r)" % (
                self._filename, self._testname, self._line_number)

        def runtest(self):
            j = self.session.stbt_run_prep
            try:
                self.session.stbt_args.test_cases = ["%s::%s" % (
                    self._filename, self._testname)]
                cmd_run_body(self.session.stbt_args, self.session.stbt_node, j)
            except requests.exceptions.HTTPError as e:
                message = "HTTP %i Error: %s" % (
                    e.response.status_code, e.response.text)
                if hasattr(e, "request"):
                    message += " during %s %s" % (
                        e.request.method, e.request.url)  # pylint:disable=no-member
                sys.stderr.write(message + '\n')
                sys.stderr.flush()
                raise
            finally:
                self.session.stbt_args.test_cases = None

        def reportinfo(self):
            return self.fspath, self._line_number, ""

    class Args(object):
        """Pretends to be the result of calling `argparser` `parse_args` so we
        can reuse code from stbt_rig for filling in the details"""
        def __init__(self, config):
            for arg in itertools.chain(ARGS, RUN_ARGS):
                dest = arg.dest or arg.longname.strip('-').replace('-', '_')
                if arg.cmdline_only:
                    setattr(self, dest, arg.default)
                else:
                    setattr(self, dest, config.getvalue(dest))

            self.test_cases = None
            self.mode = "pytest"
            self.command = "run"


    def pytest_sessionstart(session):
        args = Args(session.config)
        session.stbt_args = args
        resolve_args(session.stbt_args)

        pluginmanager = session.config.pluginmanager
        if not session.config.option.collectonly:
            pluginmanager.unregister(name="python")

        capmanager = pluginmanager.getplugin('capturemanager')
        capmanager.suspend_global_capture(in_=True)
        for portal_auth_token in iter_portal_auth_tokens(
                args.portal_url, args.portal_auth_file, args.mode):
            try:
                portal = Portal(args.portal_url, portal_auth_token)
                node = Node(portal, session.config.getvalue("node_id"))

                j = cmd_run_prep(args, portal)
                break
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
        else:
            die("Unauthorised")

        capmanager.resume_global_capture()

        session.stbt_node = node
        session.stbt_run_prep = j
except ImportError:
    # Pytest integration is optional
    pass


@contextmanager
def named_temporary_directory(suffix='', prefix='tmp', dir=None,
                              ignore_errors=False):
    dirname = tempfile.mkdtemp(suffix, prefix, dir)
    try:
        yield dirname
    finally:
        shutil.rmtree(dirname, ignore_errors=ignore_errors)


try:
    replace = os.replace
except AttributeError:
    if platform.system() == "Windows":
        replace = None
    else:
        replace = os.rename


@contextmanager
def sponge(filename):
    if not replace:
        # Can't be atomic on Windows with Python <v3.3.  Oh well.
        with open(filename, "wb") as f:
            yield f
        return

    # pylint: disable=bad-continuation
    with tempfile.NamedTemporaryFile(
            dir=os.path.dirname(filename), prefix=os.path.basename(filename),
            suffix='~', delete=False) as f:
        try:
            yield f
            f.close()
            replace(f.name, filename)
        except:
            os.remove(f.name)
            raise


def mkdir_p(d):
    """Python 3.2 has an optional argument to os.makedirs called exist_ok.  To
    support older versions of python we can't use this and need to catch
    exceptions"""
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(d) \
                and os.access(d, os.R_OK | os.W_OK):
            return
        else:
            raise


def die(message, *args):
    logger.error(message, *args)
    sys.exit(1)


def to_bytes(text):
    if isinstance(text, bytes):
        return text
    else:
        return text.encode("utf-8", errors="backslashreplace")


def to_unicode(text):
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="replace")
    else:
        return text


def to_native_str(text):
    if sys.version_info.major == 2:
        return to_bytes(text)
    else:
        return to_unicode(text)


# Python 2 & 3 compatible way of raising an exception with traceback.
# Copied from python-future so that we don't have to add a dependency.
if sys.version_info.major == 3:
    def raise_(tp, value, tb):  # pylint:disable=unused-argument
        """
        A function that matches the Python 2.x ``raise`` statement. This
        allows re-raising exceptions with the cls value and traceback on
        Python 2 and 3.
        """
        exc = value
        if exc.__traceback__ is not tb:
            raise exc.with_traceback(tb)
        raise exc

    unicode = str
else:
    # `raise a, b, c` is a syntax error on Python 3 (even though we don't run
    # this block with Python 3, Python still has to parse it). Hence `exec`.
    exec(  # pylint:disable=exec-used
        dedent('''\
        def raise_(tp, value=None, tb=None):
            raise tp, value, tb
        '''))


if __name__ == '__main__':
    sys.exit(main(sys.argv))
