"""Unit tests for the hardening engine (mocked registry & PowerShell)."""

from __future__ import annotations

from unittest.mock import patch

from laptopshield.core.hardening import HardeningEngine


def test_score_calculation_all_locked():
    engine = HardeningEngine()
    with patch("laptopshield.core.hardening.read_reg_value") as mock_read:
        def fake_read(hive, key, name):
            if name == "fDenyTSConnections":
                return 1
            if name == "fAllowToGetHelp":
                return 0
            if name == "Value":
                return "Deny"
            if name in ("LetAppsAccessCamera", "LetAppsAccessMicrophone"):
                return 2
            if name == "SMB1":
                return 0
            if name == "Start":
                return 4
            if name == "EnableMulticast":
                return 0
            if name == "Enabled":
                return 0
            if name == "NoDriveTypeAutoRun":
                return 255
            if name == "EnableFirewall":
                return 1
            return None

        mock_read.side_effect = fake_read
        statuses = engine.list_controls()
        assert len(statuses) == 9
        assert all(s.is_locked for s in statuses)
        assert engine.calculate_score(statuses) == 100


def test_score_calculation_all_exposed():
    engine = HardeningEngine()
    with patch("laptopshield.core.hardening.read_reg_value", return_value=None):
        statuses = engine.list_controls()
        # Only rdp returns False when fDenyTSConnections is None
        assert engine.calculate_score(statuses) == 0


def test_set_unknown_control():
    engine = HardeningEngine()
    res = engine.set_control("nonexistent", True)
    assert not res.success
    assert "Unknown control" in res.message


def test_lock_camera_writes_consent_store():
    engine = HardeningEngine()
    with (
        patch("laptopshield.core.hardening.write_reg_value", return_value=(True, "OK")) as mock_write,
        patch("laptopshield.core.hardening.run_powershell", return_value=(0, "", "")),
        patch(
            "laptopshield.core.hardening.read_reg_value",
            side_effect=lambda h, k, n: 2 if n == "LetAppsAccessCamera" else "Deny",
        ),
    ):
        res = engine.set_control("camera", True)
        assert res.success
        assert res.locked
        assert mock_write.call_count == 5


def test_lockdown_all_and_restore_all():
    engine = HardeningEngine()
    with (
        patch("laptopshield.core.hardening.write_reg_value", return_value=(True, "OK")),
        patch("laptopshield.core.hardening.run_powershell", return_value=(0, "", "")),
        patch("laptopshield.core.hardening.read_reg_value", return_value=None),
    ):
        locked_results = engine.lockdown_all()
        assert len(locked_results) == 9
        assert all(r.success for r in locked_results)

        restored_results = engine.restore_all()
        assert len(restored_results) == 9
        assert all(r.success for r in restored_results)
        fw_res = next(r for r in restored_results if r.control_id == "firewall")
        assert fw_res.locked is True
