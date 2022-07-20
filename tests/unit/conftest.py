"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest
from napalm.base.test.double import BaseTestDouble
from napalm_ros import ros
import typing
from librouteros.protocol import (
    parse_word,
    cast_to_api,
    compose_word,
)
from librouteros.api import Path


def eval_query(query, row):
    stack = list()
    for elem in query:
        if elem == '?#|':
            lhs, rhs = stack.pop(), stack.pop()
            stack.append(lhs or rhs)
        elif elem == '?#&':
            lhs, rhs = stack.pop(), stack.pop()
            stack.append(lhs and rhs)
        elif elem.startswith('?>'):
            elem.replace('>', '=')
            key, value = parse_word(elem[1:])
            stack.append(row[elem] > value)
        elif elem.startswith('?='):
            key, value = parse_word(elem[1:])
            stack.append(row[key] == value)
        elif elem == '?#!':
            stack.append(not stack.pop())
    return stack[0]


def parse_cmd(self, cmd: str, *words: str):
    proplist = list()
    qwords = list()
    for word in words:
        if word.startswith('=.proplist='):
            proplist = tuple(word.split('=.proplist=')[1].split(','))
        else:
            qwords.append(word)
    return proplist, qwords


def eval_cmd(cmd, words, load):
    for row in load(cmd):
        if eval_query(words, row):
            yield row


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = ros.ROSDriver
    request.cls.patched_driver = PatchedROSDevice
    request.cls.vendor = 'ros'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedROSDevice(ros.ROSDriver):
    """ROS device test double."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)
        self.patched_attrs = ['api']

    def open(self):
        self.api = FakeApi()

    def get_config(self, retrieve='all', full=False, sanitized=False):
        config = ''
        return {'running': config, 'candidate': config, 'startup': config}


class FakeApi(BaseTestDouble):

    def __call__(self, command, **kwargs):
        yield from self.load(command)

    def path(self, *path: str):
        return Path(
            path='',
            api=self,
        ).join(*path)

    def rawCmd(self, cmd, *words):
        proplist, words = parse_cmd(cmd, *words)
        print(cmd, words)
        if not words:
            yield from self.load(cmd)
        else:
            yield from eval_cmd(cmd=cmd, words=words, load=self.load)

    def close(self):
        pass

    def load(self, command):
        full_path = self.find_file(self.sanitize_text(command) + '.json')
        yield from self.read_json_file(full_path)['data']
