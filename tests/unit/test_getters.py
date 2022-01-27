"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm_ros.ros import (
    LLDPInterfaces,
)

import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""


def test_LLDPInterfaces_with_parent():
    ifaces = LLDPInterfaces.fromApi('ether1,bridge0')
    assert ifaces.parent == 'bridge0'
    assert ifaces.child == 'ether1'


def test_LLDPInterfaces_without_parent():
    ifaces = LLDPInterfaces.fromApi('ether1')
    assert ifaces.parent == ''
    assert ifaces.child == 'ether1'
