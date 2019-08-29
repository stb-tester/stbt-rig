from __future__ import (
    absolute_import, division, print_function, unicode_literals)

import logging
from collections import namedtuple
from contextlib import contextmanager

import requests

from stbt_rig import RetrySession


RetrySessionTestCtx = namedtuple(
    "RetrySessionTestCtx", "http_mock session time")


@contextmanager
def retry_session_test_ctx():
    import requests_mock

    time_ = MockTime()
    session = requests.Session()
    adapter = requests_mock.Adapter()
    session.mount('mock', adapter)

    retrysession = RetrySession(10, session=session, _time=time_)
    yield RetrySessionTestCtx(adapter, retrysession, time_)


def test_retrysession_happypath():
    with retry_session_test_ctx() as ctx:
        ctx.http_mock.register_uri('GET', '//test.com/path', text='resp')
        with ctx.time.assert_duration(seconds=0):
            assert ctx.session.get('mock://test.com/path').text == 'resp'


def test_retrysession_retry_after_500():
    with retry_session_test_ctx() as ctx:
        ctx.http_mock.register_uri(
            'GET', '//test.com/path', [
                {'text': 'bad', 'status_code': 500},
                {'text': 'ok', 'status_code': 200},
            ])
        with ctx.time.assert_duration(seconds=1):
            assert ctx.session.get('mock://test.com/path').text == 'ok'


def test_retrysession_retry_after_202():
    with retry_session_test_ctx() as ctx:
        ctx.http_mock.register_uri(
            'GET', '//test.com/path', [
                {'text': 'retry', 'status_code': 202},
                {'text': 'ok', 'status_code': 200},
            ])
        with ctx.time.assert_duration(seconds=0):
            assert ctx.session.get('mock://test.com/path').text == 'ok'


def test_retrysession_no_retry_after_400():
    with retry_session_test_ctx() as ctx:
        ctx.http_mock.register_uri(
            'GET', '//test.com/path', [
                {'text': 'bad', 'status_code': 400},
                {'text': 'ok', 'status_code': 200},
            ])
        with ctx.time.assert_duration(seconds=0):
            resp = ctx.session.get('mock://test.com/path')
            assert resp.text == 'bad'
            assert resp.status_code == 400


def test_retrysession_timeout():
    with retry_session_test_ctx() as ctx:
        ctx.http_mock.register_uri(
            'GET', '//test.com/path', text='bad', status_code=500)
        with ctx.time.assert_duration(seconds=10):
            try:
                ctx.session.get('mock://test.com/path')
                assert False, "GET should have thrown"
            except requests.HTTPError as e:
                assert e.response.text == 'bad'
                assert e.response.status_code == 500


class MockTime(object):
    def __init__(self, start_time=1500000000.):
        self._time = start_time
        self._functions = []

    def time(self):
        t = self._time
        return t

    def sleep(self, seconds):
        logging.info("time.sleep(%s)", seconds)
        while self._functions and self._functions[0][0] <= self._time + seconds:
            _, fn = self._functions.pop(0)
            fn()

        self._time += seconds

    def interrupt(self, exception):
        def raise_exception():
            raise exception
        self.at(0, raise_exception)

    def at(self, offset, function):
        self._functions.append((self._time + offset, function))
        self._functions.sort()

    @contextmanager
    def assert_duration(self, seconds):
        start_time = self._time
        yield self
        assert self._time - start_time == seconds

    @contextmanager
    def patch(self):
        from mock import patch
        with patch("time.time", self.time), \
                patch("time.sleep", self.sleep):
            yield self
