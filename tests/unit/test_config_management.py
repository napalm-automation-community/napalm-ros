"""Unit tests for the configuration-management methods of ROSDriver.

The librouteros config engine (api.config()) is mocked; these tests assert the
driver maps the NAPALM contract onto it correctly. End-to-end behaviour is covered
by integration testing against a real device.
"""
from unittest.mock import MagicMock

import pytest
from napalm.base.exceptions import (
    CommitConfirmException,
    CommitError,
    MergeConfigException,
    ReplaceConfigException,
)
from librouteros.exceptions import ConnectionClosed, TrapError
from packaging.version import parse as version_parse

from napalm_ros.ros import ROLLBACK_SNAPSHOT, REVERT_JOB, ROSDriver


def make_driver(version='7.11.2'):
    driver = ROSDriver('host', 'user', 'pass')
    driver.api = MagicMock()
    # Pin the reported RouterOS version so the commit dry-run gate is deterministic;
    # default below 7.16 so most tests exercise the no-validate path.
    driver._ros_version = MagicMock(return_value=version_parse(version))
    cfg = MagicMock()
    cfg.rollback_pending.return_value = False  # no commit-confirm pending by default
    driver.api.config.return_value = cfg
    return driver, cfg


def test_load_merge_candidate_buffers_config():
    driver, _ = make_driver()
    driver.load_merge_candidate(config='cfg')
    assert driver._candidate == 'cfg'
    assert driver._config_replace is False


def test_load_replace_candidate_sets_replace_flag():
    driver, _ = make_driver()
    driver.load_replace_candidate(config='cfg')
    assert driver._candidate == 'cfg'
    assert driver._config_replace is True


def test_read_candidate_filename_takes_precedence(tmp_path):
    path = tmp_path / 'candidate.rsc'
    path.write_text('from-file')
    assert ROSDriver._read_candidate(str(path), 'from-string') == 'from-file'


def test_read_candidate_from_string():
    assert ROSDriver._read_candidate(None, 'from-string') == 'from-string'


def test_read_candidate_neither():
    assert ROSDriver._read_candidate(None, None) == ''


def test_compare_config_delegates_to_engine():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.compare.return_value = 'the-diff'
    assert driver.compare_config() == 'the-diff'
    cfg.compare.assert_called_once_with('cand')


def test_compare_config_without_candidate_is_empty():
    driver, cfg = make_driver()
    assert driver.compare_config() == ''
    cfg.compare.assert_not_called()


def test_discard_config_clears_state():
    driver, _ = make_driver()
    driver._candidate = 'x'
    driver._config_replace = True
    driver.discard_config()
    assert driver._candidate is None
    assert driver._config_replace is False


def test_commit_config_message_not_implemented():
    driver, _ = make_driver()
    driver._candidate = 'x'
    with pytest.raises(NotImplementedError):
        driver.commit_config(message='nope')


def test_commit_config_without_candidate_raises():
    driver, _ = make_driver()
    with pytest.raises(CommitError):
        driver.commit_config()


def test_commit_merge_snapshots_then_applies():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver.commit_config()
    cfg.backup_save.assert_called_once_with(ROLLBACK_SNAPSHOT, persistent=True)
    cfg.apply.assert_called_once_with('cand')
    cfg.arm_rollback.assert_not_called()
    # the snapshot must capture the PRE-change state, i.e. run before apply
    order = [c[0] for c in cfg.mock_calls]
    assert order.index('backup_save') < order.index('apply')
    assert driver._candidate is None


def test_commit_replace_snapshots_before_replace():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver._config_replace = True
    driver.commit_config()
    order = [c[0] for c in cfg.mock_calls]
    assert order.index('backup_save') < order.index('replace')


def test_commit_rollback_prep_failure_raises_commit_error():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.backup_save.side_effect = TrapError(message='no space')
    with pytest.raises(CommitError):
        driver.commit_config()
    cfg.apply.assert_not_called()


def test_commit_revert_in_blocked_by_device_mode_is_actionable():
    # RouterOS 7.17+ can gate the scheduler behind device-mode; arm_rollback's scheduler
    # add is then refused. The error should name the fix, and the candidate must not apply.
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.arm_rollback.side_effect = TrapError(message='not allowed by device-mode')
    with pytest.raises(CommitError) as excinfo:
        driver.commit_config(revert_in=120)
    msg = str(excinfo.value)
    assert 'device-mode' in msg
    assert 'scheduler=yes' in msg
    cfg.apply.assert_not_called()


def test_commit_revert_in_other_arm_failure_keeps_generic_error():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.arm_rollback.side_effect = TrapError(message='no space')
    with pytest.raises(CommitError) as excinfo:
        driver.commit_config(revert_in=120)
    assert 'Failed to prepare rollback' in str(excinfo.value)
    cfg.apply.assert_not_called()


def test_commit_merge_revert_in_arms_scheduler():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver.commit_config(revert_in=120)
    cfg.arm_rollback.assert_called_once_with(120, name=REVERT_JOB)
    cfg.apply.assert_called_once_with('cand')
    # a snapshot is still taken so rollback() reverts this commit even after confirm
    cfg.backup_save.assert_called_once_with(ROLLBACK_SNAPSHOT, persistent=True)


def test_commit_rejected_while_commit_confirm_pending():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.rollback_pending.return_value = True
    with pytest.raises(CommitError):
        driver.commit_config()
    cfg.apply.assert_not_called()
    cfg.arm_rollback.assert_not_called()


def test_commit_replace_calls_replace():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver._config_replace = True
    driver.commit_config()
    cfg.backup_save.assert_called_once_with(ROLLBACK_SNAPSHOT, persistent=True)
    cfg.replace.assert_called_once_with('cand')


def test_commit_replace_with_revert_in_rejected():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver._config_replace = True
    with pytest.raises(CommitConfirmException):
        driver.commit_config(revert_in=60)
    cfg.replace.assert_not_called()


def test_commit_merge_error_wrapped_as_merge_exception():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.apply.side_effect = TrapError(message='syntax error')
    with pytest.raises(MergeConfigException):
        driver.commit_config()


def test_commit_failure_with_revert_in_cancels_armed_rollback():
    # If the apply fails after arming a revert, the armed auto-revert is cancelled so the
    # device does not reboot out from under the operator and has_pending_commit is cleared.
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.apply.side_effect = TrapError(message='syntax error')
    with pytest.raises(MergeConfigException):
        driver.commit_config(revert_in=120)
    cfg.cancel_rollback.assert_called_once_with(name=REVERT_JOB)


def test_commit_failure_without_revert_in_has_no_rollback_to_cancel():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    cfg.apply.side_effect = TrapError(message='syntax error')
    with pytest.raises(MergeConfigException):
        driver.commit_config()
    cfg.cancel_rollback.assert_not_called()


def test_commit_replace_error_wrapped_as_replace_exception():
    driver, cfg = make_driver()
    driver._candidate = 'cand'
    driver._config_replace = True
    cfg.replace.side_effect = TrapError(message='boom')
    with pytest.raises(ReplaceConfigException):
        driver.commit_config()


def test_commit_dry_run_validates_before_apply_on_7_16():
    driver, cfg = make_driver(version='7.16.1')
    driver._candidate = 'cand'
    driver.commit_config()
    cfg.validate.assert_called_once_with('cand')
    # validation runs before anything on the device is touched
    order = [c[0] for c in cfg.mock_calls]
    assert order.index('validate') < order.index('backup_save')
    assert order.index('validate') < order.index('apply')


def test_commit_dry_run_failure_aborts_before_snapshot():
    driver, cfg = make_driver(version='7.16.1')
    driver._candidate = 'cand'
    cfg.validate.side_effect = TrapError(message='syntax error')
    with pytest.raises(MergeConfigException):
        driver.commit_config()
    # nothing on the device is touched when the dry-run rejects the candidate
    cfg.backup_save.assert_not_called()
    cfg.apply.assert_not_called()


def test_commit_dry_run_failure_on_replace_raises_replace_exception():
    driver, cfg = make_driver(version='7.16.1')
    driver._candidate = 'cand'
    driver._config_replace = True
    cfg.validate.side_effect = TrapError(message='syntax error')
    with pytest.raises(ReplaceConfigException):
        driver.commit_config()
    cfg.replace.assert_not_called()


def test_commit_skips_dry_run_below_7_16():
    driver, cfg = make_driver(version='7.15.3')
    driver._candidate = 'cand'
    driver.commit_config()
    cfg.validate.assert_not_called()
    cfg.apply.assert_called_once_with('cand')


def test_commit_skips_dry_run_when_disabled():
    driver, cfg = make_driver(version='7.16.1')
    driver.validate_before_commit = False
    driver._candidate = 'cand'
    driver.commit_config()
    cfg.validate.assert_not_called()
    cfg.apply.assert_called_once_with('cand')


def test_has_pending_commit_delegates():
    driver, cfg = make_driver()
    cfg.rollback_pending.return_value = True
    assert driver.has_pending_commit() is True
    cfg.rollback_pending.assert_called_once_with(name=REVERT_JOB)


def test_confirm_commit_cancels_scheduler():
    driver, cfg = make_driver()
    driver.confirm_commit()
    cfg.cancel_rollback.assert_called_once_with(name=REVERT_JOB)


def test_rollback_pending_restores_revert_backup():
    driver, cfg = make_driver()
    cfg.rollback_pending.return_value = True
    driver.rollback()
    cfg.backup_load.assert_called_once_with(REVERT_JOB, persistent=True)


def test_rollback_restores_snapshot_when_not_pending():
    driver, cfg = make_driver()
    cfg.rollback_pending.return_value = False
    cfg.backup_exists.return_value = True
    driver.rollback()
    cfg.backup_load.assert_called_once_with(ROLLBACK_SNAPSHOT, persistent=True)


def test_rollback_without_snapshot_raises():
    driver, cfg = make_driver()
    cfg.rollback_pending.return_value = False
    cfg.backup_exists.return_value = False
    with pytest.raises(CommitError):
        driver.rollback()
    cfg.backup_load.assert_not_called()


def test_is_alive_true_when_api_responds():
    driver, _ = make_driver()
    driver.api.return_value = iter([{'name': 'MikroTik'}])
    assert driver.is_alive() == {'is_alive': True}


def test_is_alive_false_on_dropped_connection():
    driver, _ = make_driver()
    driver.api.side_effect = ConnectionClosed('connection dropped')
    assert driver.is_alive() == {'is_alive': False}


def test_is_alive_false_when_not_opened():
    driver = ROSDriver('host', 'user', 'pass')  # open() never called, so api is None
    assert driver.is_alive() == {'is_alive': False}
