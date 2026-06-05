import json
import subprocess
import sys

TRAPS = [
    "LEAK_TRAP_MCP_ENV_VALUE",
    "LEAK_TRAP_MCP_HEADER_VALUE",
    "LEAK_TRAP_PLUGIN_MANIFEST_SECRET",
    "LEAK_TRAP_PLUGIN_SYMLINK_BODY",
]


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "hermes_system_doctor.cli", *args],
        text=True,
        capture_output=True,
        check=False,
    )


def check_by_name(data: dict, name: str) -> dict:
    return next(check for check in data["checks"] if check["name"] == name)


def assert_no_traps(output: str):
    for trap in TRAPS:
        assert trap not in output


def test_mcp_safe_inventory_reports_config_shape_without_secret_values(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("PRESENT_MCP_HEADER_TEST_VAR=not-a-real-secret\n", encoding="utf-8")
    (home / "config.yaml").write_text(
        "mcp_servers:\n"
        "  local_time:\n"
        "    command: python\n"
        "    args: ['-m', 'time_server']\n"
        "    env:\n"
        "      SAFE_MODE: '1'\n"
        "      API_TOKEN: LEAK_TRAP_MCP_ENV_VALUE\n"
        "      REF_TOKEN: ${MISSING_MCP_ENV_TEST_VAR}\n"
        "  broken:\n"
        "    args: bad\n"
        "  remote:\n"
        "    url: http://example.com/mcp\n"
        "    headers:\n"
        "      Authorization: LEAK_TRAP_MCP_HEADER_VALUE\n"
        "      X-Api-Key: ${MISSING_MCP_HEADER_TEST_VAR}\n"
        "  remote_env_bearer:\n"
        "    url: https://example.com/mcp\n"
        "    headers:\n"
        "      Authorization: Bearer ${PRESENT_MCP_HEADER_TEST_VAR}\n",
        encoding="utf-8",
    )
    result = run_cli("full", "--hermes-home", str(home), "--json")
    assert result.returncode == 0
    assert_no_traps(result.stdout)
    data = json.loads(result.stdout)
    mcp = check_by_name(data, "mcp")
    ids = {finding["id"] for finding in mcp["findings"]}
    assert "mcp.transport_missing" in ids
    assert "mcp.inline_secret_env" in ids
    assert "mcp.inline_secret_header" in ids
    assert "mcp.env_ref_missing" in ids
    assert "mcp.header_env_ref_missing" in ids
    assert "mcp.http_without_tls" in ids
    assert mcp["facts"]["tools_executed"] == "not_run"
    assert mcp["facts"]["network_probes"] == "not_run"


def test_mcp_command_path_escape_is_not_green(tmp_path):
    home = tmp_path / "hermes"
    outside = tmp_path / "outside"
    home.mkdir()
    outside.mkdir()
    (outside / "server").write_text("do not execute", encoding="utf-8")
    (home / "config.yaml").write_text(
        "mcp_servers:\n"
        "  escape:\n"
        "    command: ../outside/server\n",
        encoding="utf-8",
    )
    result = run_cli("full", "--hermes-home", str(home), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    mcp = check_by_name(data, "mcp")
    ids = {finding["id"] for finding in mcp["findings"]}
    assert "mcp.command_missing" in ids


def test_plugins_inventory_reports_manifests_without_secret_values(tmp_path):
    home = tmp_path / "hermes"
    plugin_dir = home / "plugins" / "good"
    bad_dir = home / "plugins" / "bad"
    plugin_dir.mkdir(parents=True)
    bad_dir.mkdir(parents=True)
    (home / "config.yaml").write_text(
        "plugins:\n"
        "  good:\n"
        "    enabled: true\n"
        "  missing-plugin:\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    (plugin_dir / "plugin.yaml").write_text(
        "name: good\n"
        "description: Safe plugin metadata.\n"
        "api_token: LEAK_TRAP_PLUGIN_MANIFEST_SECRET\n",
        encoding="utf-8",
    )
    (bad_dir / "plugin.yaml").write_text("name: [broken", encoding="utf-8")
    result = run_cli("full", "--hermes-home", str(home), "--json")
    assert result.returncode == 0
    assert_no_traps(result.stdout)
    data = json.loads(result.stdout)
    plugins = check_by_name(data, "plugins")
    ids = {finding["id"] for finding in plugins["findings"]}
    assert "plugins.inline_secret_metadata" in ids
    assert "plugins.manifest_invalid" in ids
    assert "plugins.configured_missing" in ids
    assert plugins["facts"]["payloads_executed"] == "not_run"


def test_plugin_symlinks_are_skipped_without_reading_targets(tmp_path):
    home = tmp_path / "hermes"
    outside = tmp_path / "outside-plugin"
    plugins_root = home / "plugins"
    plugins_root.mkdir(parents=True)
    outside.mkdir()
    (home / "config.yaml").write_text("plugins: []\n", encoding="utf-8")
    (outside / "plugin.yaml").write_text(
        "name: outside\ndescription: LEAK_TRAP_PLUGIN_SYMLINK_BODY\n",
        encoding="utf-8",
    )
    (plugins_root / "outside").symlink_to(outside)
    result = run_cli("full", "--hermes-home", str(home), "--json")
    assert result.returncode == 0
    assert "LEAK_TRAP_PLUGIN_SYMLINK_BODY" not in result.stdout
    data = json.loads(result.stdout)
    plugins = check_by_name(data, "plugins")
    ids = {finding["id"] for finding in plugins["findings"]}
    assert "plugins.symlink_skipped" in ids


def test_plugins_and_mcp_are_available_from_full_report_fixture():
    result = run_cli("full", "--hermes-home", "tests/fixtures/hermes_home_minimal", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    check_names = {check["name"] for check in data["checks"]}
    assert "plugins" in check_names
    assert "mcp" in check_names
