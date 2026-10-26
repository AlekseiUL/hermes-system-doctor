import pytest

from hermes_system_doctor.checks import gateway, mcp, plugins
from hermes_system_doctor.fix_executor import _actions, load_repair_plan
from hermes_system_doctor.repair_plan import load_report


@pytest.mark.parametrize("loader", [load_repair_plan, load_report])
def test_invalid_serialized_object_remains_value_error(tmp_path, loader):
    source = tmp_path / "invalid.json"
    source.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        loader(source)


def test_invalid_serialized_actions_remains_value_error():
    with pytest.raises(ValueError, match="must be a list"):
        _actions({"actions": "not-a-list"})


@pytest.mark.parametrize("module", [gateway, mcp, plugins])
@pytest.mark.parametrize("payload", [b"broken: [", b"invalid: \xff", b"date: 2026-99-99"])
def test_untrusted_config_parse_failure_is_reported(tmp_path, module, payload):
    source = tmp_path / "config.yaml"
    source.write_bytes(payload)
    config, error = module._load_config(source)
    assert config is None
    assert error


@pytest.mark.parametrize("module", [gateway, mcp, plugins])
def test_recursive_config_failure_is_reported(tmp_path, monkeypatch, module):
    source = tmp_path / "config.yaml"
    source.write_text("{}", encoding="utf-8")

    def fail_parse(_text):
        raise RecursionError("synthetic parser limit")

    monkeypatch.setattr(module.yaml, "safe_load", fail_parse)
    assert module._load_config(source) == (None, "RecursionError")
