#!/usr/bin/python

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from ConfigParser import SafeConfigParser

import requests
from enum import Enum

# pylint: disable=protected-access

logger = logging.getLogger("stbt_rig")


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    run_parser = sub.add_parser('run', help="Run a test-case")
    run_parser.add_argument(
        "--force", action="store_true",
        help=("Don't fail if the node is in use, interrupt the existing job "
              "instead"))
    run_parser.add_argument("--portal-url")

    # Shouldn't pass auth token in on command line - otherwise it will be visible
    # in /proc.  Pass it in a file instead.
    run_parser.add_argument(
        "--portal-auth-file",
        help="name of file containing the HTTP REST API authentication token")

    run_parser.add_argument("--node-id")
    run_parser.add_argument("--git-remote")

    run_group = run_parser.add_mutually_exclusive_group(required=True)
    run_group.add_argument("test_case", nargs='?')
    run_group.add_argument("-c")
    ss_parser = sub.add_parser('screenshot', help="Save a screenshot to disk")
    ss_parser.add_argument("filename", default="screenshot.png", nargs='?')
    args = parser.parse_args(argv[1:])

    config_parser = SafeConfigParser()
    config_parser.read('.stbt.conf')

    portal_url = args.portal_url or config_parser.get('test_pack', 'portal_url')
    node_id = args.node_id or config_parser.get('test_pack', 'node_id')

    testpack = TestPack(remote=args.git_remote)
    out = None

    for portal_auth_token in try_portal_auth_tokens(
            args.portal_auth_file, portal_url):

        portal = Portal(portal_url, portal_auth_token)
        node = Node(portal, node_id)

        try:
            if args.command == "run":
                out = cmd_run(args, testpack, portal, node)
            elif args.command == "screenshot":
                out = cmd_screenshot(args, node)
            else:
                raise AssertionError(
                    "Unreachable: Unknown command %r.  argparse should prevent this" %
                    args.command)
            break
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                # Unauthorised, try again, but with a new password
                pass
            else:
                raise


def cmd_run(args, testpack, portal, node):
    commit_sha = testpack.push_git_snapshot()
    job = node.run_tests(
        commit_sha, [args.test_case], await_completion=True, force=args.force)
    result = job.list_results()[0]
    result.print_logs()
    if result.is_ok():
        return 0
    else:
        return 1


def cmd_screenshot(args, node):
    node.save_screenshot(args.filename)


def try_portal_auth_tokens(portal_auth_file, portal_url):
    if portal_auth_file:
        with open(portal_auth_file) as f:
            yield f.read().strip()
            return

    while True:
        try:
            import keyring
            out = keyring.get_password(portal_url, "")
            if out:
                yield out
        except ImportError:
            pass

        sys.stderr.write('Enter Token for portal %r: ' % portal_url)
        token = sys.stdin.readline().strip()
        if token:
            keyring.set_password(portal_url, "", token)
            yield token
        sys.stderr.write("Authentication Failure\n")


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
    class Status(Enum):
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
        if self.get_status() != TestJob.Status.EXITED:
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
            if self.get_status() != TestJob.Status.RUNNING:
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

    def get_status(self):
        if self._json.get('status') == 'exited':
            # If we were "exited" in the past, then we'll still be "exited" now:
            # Save making another HTTP request
            return TestJob.Status.EXITED
        self._update()
        return TestJob.Status(self.json['status'])

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
        self.json = self._get().json()


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
        if job.get_status() == TestJob.Status.RUNNING:
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
            force=False, timeout=None, await_completion=False,
            assert_pass=False):
        if force:
            Node(self, node_id).stop_current_job()

        kwargs = {}
        if remote_control is not None:
            kwargs['remote_control'] = remote_control
        if category is not None:
            kwargs['category'] = category
        if soak is not None:
            kwargs['soak'] = soak
        if shuffle is not None:
            kwargs['shuffle'] = shuffle

        kwargs["node_id"] = node_id
        kwargs["test_pack_revision"] = test_pack_revision
        kwargs["test_cases"] = test_cases
        result = self._post('/api/v2/run_tests', json=kwargs)
        if result.status_code == 409:  # 409 CONFLICT
            raise NodeBusyException(
                "Couldn't run test-job on node %s.  Node is currently in use.  "
                "Specify --force to stop current job before running new one" %
                node_id)
        if not result.ok:
            logger.warning("Running tests failed.  Server said:\n%s",
                           result.content)
        result.raise_for_status()
        job = TestJob(self, job_json=result.json())

        if not await_completion:
            return job

        with job:
            job.await_completion(timeout=timeout)

            if assert_pass:
                # Show logs of each test, in case any of them failed.
                counts = job.json['result_counts']
                assert counts['pass'] == counts['total']

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
    def __init__(self, root=None, remote="origin", user_branch_prefix=None):
        if root is None:
            root = os.curdir
        self.root = root
        self.remote = remote

        if user_branch_prefix is None:
            user_branch_prefix = self._git([
                'config', 'user.email']).strip().split('@')[0]
        self.user_branch_prefix = user_branch_prefix

    def _git(self, cmd, capture_output=True, extra_env=None, **kwargs):
        if capture_output:
            call = subprocess.check_output
        else:
            call = subprocess.check_call

        env = kwargs.get('env', os.environ).copy()
        if extra_env:
            env.update(extra_env)

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
        with tempfile.NamedTemporaryFile(
                prefix="index-snapshot-") as tmp_index:
            git_dir = self._git(['rev-parse', '--git-dir']).strip()
            shutil.copyfile('%s/index' % git_dir, tmp_index.name)
            self._git(['add', '-u'],
                      extra_env={'GIT_INDEX_FILE': tmp_index.name})
            write_tree = self._git(
                ['write-tree'],
                extra_env={'GIT_INDEX_FILE': tmp_index.name}).strip()

        if self.get_sha(obj_type="tree") == write_tree:
            return base_commit
        else:
            return self._git(
                ['commit-tree', write_tree, '-p', base_commit, '-m',
                 "snapshot"]).strip()

    def push_git_snapshot(self):
        commit_sha = self.take_snapshot()
        self._git([
            'push', '--quiet', '--force', self.remote,
            '%s:refs/heads/%s/wip-snapshot' % (
                commit_sha, self.user_branch_prefix)])
        return commit_sha


if __name__ == '__main__':
    sys.exit(main(sys.argv))
