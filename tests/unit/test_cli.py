"""Unit tests for ROSDriver.cli().

The API is mocked; these tests assert the driver maps each command onto
/execute (as-string on RouterOS 7, file-based on RouterOS 6) and returns the
output keyed by command. Live behaviour is covered by testing against CHR VMs.
"""
from unittest.mock import MagicMock, call

import pytest
from librouteros.exceptions import MultiTrapError, TrapError
from napalm.base.exceptions import CommandErrorException

from napalm_ros.ros import ROSDriver


def make_driver():
    driver = ROSDriver('host', 'user', 'pass')
    driver.api = MagicMock()
    return driver


def test_cli_runs_each_command_through_execute_as_string():
    driver = make_driver()
    driver.api.side_effect = [
        iter([{
            'ret': 'Flags: X - disabled\r\n 0   192.0.2.1/24  ether1'
        }]),
        iter([{
            'ret': 'router'
        }]),
    ]
    result = driver.cli(['/ip/address/print', ':put [/system/identity/get name]'])
    assert result == {
        '/ip/address/print': 'Flags: X - disabled\n 0   192.0.2.1/24  ether1',
        ':put [/system/identity/get name]': 'router',
    }
    assert driver.api.call_args_list == [
        call('/execute', script='/ip/address/print', **{'as-string': True}),
        call('/execute', script=':put [/system/identity/get name]', **{'as-string': True}),
    ]
    assert driver._execute_as_string is True


def test_cli_as_string_empty_output_when_script_prints_nothing():
    driver = make_driver()
    driver.api.return_value = iter([])  # bare !done, no =ret=
    assert driver.cli(['/system/identity/set name=router']) == {'/system/identity/set name=router': ''}


def test_cli_falls_back_to_file_on_routeros6():
    driver = make_driver()
    # 1: as-string rejected, 2: /execute file= returns job id, 3: job list (job still
    # running), 4: job list (gone), 5: /file print.
    driver.api.side_effect = [
        TrapError(message='unknown parameter'),
        iter([{
            'ret': '*4'
        }]),
        iter([{
            '.id': '*4',
            'type': 'command'
        }]),
        iter([]),
    ]
    file_path = driver.api.path.return_value
    file_path.select.return_value.where.side_effect = [
        iter([{
            'size': 8,
            'contents': 'router\r\n'
        }]),  # read
        iter([{
            '.id': '*A'
        }]),  # cleanup lookup
    ]
    assert driver.cli(['/system identity print']) == {'/system identity print': 'router'}
    assert driver._execute_as_string is False
    assert driver.api.call_args_list[0] == call('/execute', script='/system identity print', **{'as-string': True})
    exec_call = driver.api.call_args_list[1]
    assert exec_call.args == ('/execute', )
    assert exec_call.kwargs['script'] == '/system identity print'
    assert exec_call.kwargs['file'].startswith('napalm-cli-')
    file_path.remove.assert_called_once_with('*A')


def test_cli_file_mode_is_sticky_and_handles_empty_file():
    driver = make_driver()
    driver._execute_as_string = False  # detected earlier in the session
    driver.api.side_effect = [iter([{'ret': '*9'}]), iter([])]
    driver.api.path.return_value.select.return_value.where.side_effect = [
        iter([{
            'size': 0
        }]),  # RouterOS 7 exposes no 'contents' for an empty file
        iter([]),
    ]
    assert driver.cli(['/system identity set name=x']) == {'/system identity set name=x': ''}
    assert driver.api.call_args_list[0] == call(
        '/execute', script='/system identity set name=x', file=driver.api.call_args_list[0].kwargs['file']
    )


def test_cli_file_mode_rejects_output_too_large_for_inline_read():
    driver = make_driver()
    driver._execute_as_string = False
    driver.api.side_effect = [iter([{'ret': '*9'}]), iter([])]
    driver.api.path.return_value.select.return_value.where.side_effect = [
        iter([{
            'size': 16800
        }]),  # no 'contents' key: too large
        iter([{
            '.id': '*B'
        }]),
    ]
    with pytest.raises(CommandErrorException, match='16800 bytes'):
        driver.cli(['/export'])
    driver.api.path.return_value.remove.assert_called_once_with('*B')  # temp file still cleaned up


def test_cli_other_trap_raises_command_error():
    driver = make_driver()
    driver.api.side_effect = TrapError(message='not enough permissions')
    with pytest.raises(CommandErrorException, match='not enough permissions'):
        driver.cli(['/ip/address/print'])
    assert driver._execute_as_string is None  # nothing learned about as-string support


def test_cli_multitrap_raises_command_error():
    driver = make_driver()
    driver.api.side_effect = MultiTrapError(TrapError(message='one'), TrapError(message='two'))
    with pytest.raises(CommandErrorException):
        driver.cli(['/nonsense'])


def test_cli_rejects_non_text_encoding():
    driver = make_driver()
    with pytest.raises(NotImplementedError):
        driver.cli(['/ip/address/print'], encoding='json')
    driver.api.assert_not_called()


def test_cli_rejects_non_list():
    driver = make_driver()
    with pytest.raises(TypeError):
        driver.cli('/ip/address/print')
    driver.api.assert_not_called()
