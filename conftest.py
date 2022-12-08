import os
import random
import shutil
import threading
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
    subprocess.check_call(['git', 'symbolic-ref', 'HEAD', 'refs/heads/main'],
                          cwd=tp())

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
        ['git', 'push', '-u', 'origin', 'main:mybranch'], cwd=tp())


class PortalMock(object):
    def __init__(self):
        import flask
        self.app = flask.Flask(__name__)
        self.expectations = []
        self.address = None
        self.last_user_agent = None

        self.nodes = ["stb-tester-00044b5af1d3", "stb-tester-00044b5aff8a"]

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
        def _check_auth():
            if flask.request.path.startswith('/unauthorised.git'):
                # Used for testing git username prompt behaviour
                response = flask.make_response("Unauthorized", 401,
                    {'WWW-Authenticate':'Basic realm="Login Required"'})
                return response
            if (flask.request.headers.get('Authorization') !=
                    "token this is my token"):
                return ("Forbidden", 403)

            self.last_user_agent = flask.request.headers.get('User-Agent')
            return None

        @self.app.route("/ready")
        def _ready():
            return "Ready"

        @self.app.route('/api/v2/user')
        def _get_user():
            return flask.jsonify({"login": "tester"})

        @self.app.route('/api/v2/jobs/mynode/6Pfq/167')
        def _get_job():
            return flask.jsonify({'status': 'exited'})

        @self.app.route('/api/v2/jobs/mynode/6Pfq/167/await_completion')
        def _await_completion():
            return "{}", random.choice([200, 202, 202, 202])

        @self.app.route('/api/v2/results')
        def _get_results():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            out = [dict(x) for x in RESULTS]
            for x in out:
                del x['artifacts']
            return flask.jsonify(out)

        @self.app.route('/api/v2/results.xml')
        def _get_results_xml():
            assert flask.request.args['filter'] == 'job:/mynode/6Pfq/167'
            assert flask.request.args['include_tz'] == 'true'
            return PortalMock.RESULTS_XML

        @self.app.route('/api/v2/results/<path:result_id>')
        def _get_results_details(result_id):
            return flask.jsonify([
                x for x in RESULTS if x['result_id'] == '/' + result_id][0])

        @self.app.route(
                '/api/v2/results/mynode/6Pfq/167/2018-10-10T13:13:20/artifacts'
                '/<path:path>')
        def _get_artifact(path):
            return "Downloaded %r" % path, 200

        @self.app.route(
            "/api/v2/results/mynode/6Pfq/167/2018-10-10T13:13:20/stbt.log")
        def _get_stbt_log():
            return "The log output\n"

        @self.app.route('/api/v2/run_tests', methods=['POST'])
        def _post_run_tests():
            return flask.jsonify(self.on_run_tests(flask.request.json))

        @self.app.route('/api/_private/workgroup')
        def _get_private_workgroup():
            return flask.jsonify([{"id": node} for node in self.nodes])

        @self.app.route('/api/v2/secrets.pub.pem')
        def _get_secrets_pub_pem():
            return dedent("""\
                -----BEGIN PUBLIC KEY-----
                MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3ktIFPwW+Bzyy1zGJq8T
                4fPegKB69NAkmQg0tCzbi8cjItq5xhbaNZ3ALv7mSjzeDP3EYXXh5Holt5fw7Ocj
                2p+iNL7NcsNzJmrAnQxAYxHy1Dv3QBKf+TOcbwlARwgY3nRSmAk0WqkjTGb1RADr
                ZRmwcfD0H0AHNKTzNCYlM9AC/p1CzA2IXAIJRMGUkRCOM0C7938PvToJQPXZ4Pqe
                Y76jdZsQAZp/FMIZj/rTOIpPbEPWPYdicbDNgkVOQr+4/MJHhuFsnUhkbACmlVf0
                TjisY3et7ax66lyfwmLdQG3TeJKcC2AFzgfsJtIf5XEY9oHkBR0mimgKirTyNB9k
                Zz7CIas9r/BzZOod+2Mem3of/Jib0TQ3Dt5pL4XGPfQ0vJ47nBQgVNWAngaiDOLl
                C9Te8Lc9qiHQlYF+cgzYom1vR9VpZftVdEVNOiRwD/y7J6XdrOZ6nX7NviR2IxV7
                X48Qha13l2lwm9yb+xSBzf26uCcFUOCOJNNS4ZnN0JtO90dw3AsXPhjCOHzjTVki
                i2/ScQpKChXmr3ST7Hh5ZrhaCh0dAUwQ2SY/+Qk7zFVZ8wZmVTnhgRlAGUcYlzGz
                Yroa0yq1KYyUxlwtr3wyZlZMKUmFE1827oX1zo2Bj9Zqkx4OMk9exD9zftOeieYn
                26FzCmsrMBGi9mgIwC8mR28CAwEAAQ==
                -----END PUBLIC KEY-----
                """)

    def __enter__(self):
        from werkzeug.serving import make_server
        from werkzeug.debug import DebuggedApplication

        server = make_server('localhost', 0, DebuggedApplication(self.app))
        self.address = server.socket.getsockname()

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        return self

    def __exit__(self, *_):
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


def main():
    import time

    with PortalMock() as m, stbt_rig.named_temporary_directory(
            prefix="stbt-rig-selftest-", ignore_errors=True) as tmpdir:
        setup_test_pack(tmpdir, m.url)
        print("Test pack at %s/test-pack\nListening on %s" % (tmpdir, m.url))
        time.sleep(10000000)


def _find_file(path, root=os.path.dirname(os.path.abspath(__file__))):
    return os.path.join(root, path)


if __name__ == "__main__":
    main()
