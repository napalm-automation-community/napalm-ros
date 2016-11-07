from napalm_ros.ros import to_seconds

import pytest


@pytest.mark.parametrize('passed, expected', (
        ('60s', 60),
        ('6s', 6),
        ('1m10s', 70),
        ('1h1m10s', 3670),
        ('1d1h1m10s', 90070),
        ('1w1d1h1m10s', 694870),
    ))
def test_to_seconds(passed, expected):
    assert to_seconds(passed) == expected
