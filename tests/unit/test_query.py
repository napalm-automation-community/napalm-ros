import re

import pytest

from napalm_ros.query import Keys

# RouterOS attribute names are lowercase words joined by hyphens (dots on some 7.x menus).
# RouterOS 6 stops reading .proplist at the first name it doesn't know and drops every
# attribute after it, so a misspelt key there silently empties other fields.
ROS_NAME = re.compile(r"^[a-z0-9]+([.-][a-z0-9]+)*$")


@pytest.mark.parametrize("name", sorted(str(v) for k, v in vars(Keys).items() if not k.startswith("_")))
def test_key_names(name):
    assert ROS_NAME.match(name)
