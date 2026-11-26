"""Tests for USB info capture utilities."""
from tegra_fuzz.usb_info import save_hardware_snapshot


def test_save_hardware_snapshot_with_device_id(tmp_path):
    device_id = bytes.fromhex("40810205000000080047506401101062")
    out = save_hardware_snapshot(tmp_path / "hw.json", device_id=device_id)
    assert out.exists()

    import json
    data = json.loads(out.read_text())
    assert data["device_id_hex"] == "40810205000000080047506401101062"
    assert data["parsed_id"]["chip"] == "T210 (Erista)"
    assert "A02" in data["parsed_id"]["revision"]


def test_save_hardware_snapshot_without_device(tmp_path):
    out = save_hardware_snapshot(tmp_path / "hw.json")
    assert out.exists()

    import json
    data = json.loads(out.read_text())
    assert isinstance(data, dict)
