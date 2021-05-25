"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm_ros.ros import (
    LLDPInterfaces,
)

import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""


def test_LLDPInterfaces_obj_str():
    obj = LLDPInterfaces(parent='bridge0', child='ether1')
    assert str(obj) == 'bridge0/ether1'


def test_LLDPInterfaces_fromAPI():
    obj = LLDPInterfaces.fromApi('ether1,bridge0')
    assert str(obj) == 'bridge0/ether1'
