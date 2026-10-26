import json
import subprocess
import sys


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "hermes_system_doctor.cli", *args],
        text=True,
        capture_output=True,
        check=False,
    )


def test_discover_fixture_json(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: test\n", encoding="utf-8")
    result = run_cli("discover", "--hermes-home", str(home), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["mode"] == "discover"
    assert data["status"] == "OK"


def test_missing_home_fail_on_fail(tmp_path):
    missing = tmp_path / "missing"
    result = run_cli("quick", "--hermes-home", str(missing), "--fail-on", "fail")
    assert result.returncode == 2
    assert "home.missing" in result.stdout


def test_quick_multi_profile_fixture_reports_profiles():
    result = run_cli(
        "quick",
        "--hermes-home",
        "tests/fixtures/hermes_home_multi_profile",
        "--json",
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "OK"
    discovery = next(c for c in data["checks"] if c["name"] == "discovery")
    assert discovery["facts"]["profiles_count"] == 3


def test_all_profiles_flag_is_accepted_for_preview_quickstart():
    result = run_cli(
        "quick",
        "--all-profiles",
        "--hermes-home",
        "tests/fixtures/hermes_home_multi_profile",
        "--json",
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "OK"


def test_broken_config_returns_fail():
    result = run_cli(
        "quick",
        "--hermes-home",
        "tests/fixtures/hermes_home_broken_config",
        "--json",
        "--fail-on",
        "fail",
    )
    assert result.returncode == 2
    data = json.loads(result.stdout)
    findings = [f for c in data["checks"] for f in c["findings"]]
    assert any(f["id"] == "config.parse_error" for f in findings)


def test_cron_missing_script_and_workdir_are_reported():
    result = run_cli(
        "full",
        "--hermes-home",
        "tests/fixtures/hermes_home_with_cron_issue",
        "--json",
        "--fail-on",
        "fail",
    )
    assert result.returncode == 2
    data = json.loads(result.stdout)
    findings = [f for c in data["checks"] for f in c["findings"]]
    ids = {f["id"] for f in findings}
    assert "cron.script_missing" in ids
    assert "cron.workdir_missing" in ids
    assert ("/Us" + "ers/") not in result.stdout


def test_cron_relative_script_under_scripts_dir_is_accepted(tmp_path):
    home = tmp_path / "hermes"
    scripts = home / "scripts"
    cron = home / "cron"
    scripts.mkdir(parents=True)
    cron.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: test\n", encoding="utf-8")
    (scripts / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (cron / "jobs.json").write_text(
        '{"jobs":[{"id":"ok-job","script":"ok.py"}]}\n', encoding="utf-8"
    )
    result = run_cli("quick", "--hermes-home", str(home), "--json", "--fail-on", "fail")
    assert result.returncode == 0, result.stdout
    assert "cron.script_missing" not in result.stdout


def test_cron_script_path_traversal_is_not_green(tmp_path):
    root = tmp_path
    home = root / "hermes"
    outside = root / "outside"
    cron = home / "cron"
    home.mkdir()
    outside.mkdir()
    cron.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: test\n", encoding="utf-8")
    (outside / "external.py").write_text("print('outside')\n", encoding="utf-8")
    (cron / "jobs.json").write_text(
        '{"jobs":[{"id":"escape","script":"../outside/external.py"}]}\n',
        encoding="utf-8",
    )
    result = run_cli("quick", "--hermes-home", str(home), "--json")
    data = json.loads(result.stdout)
    findings = [f for c in data["checks"] for f in c["findings"]]
    assert any(f["id"] == "cron.script_outside_profile" for f in findings)
    assert str(outside) not in result.stdout


def test_absolute_hermes_home_is_redacted_in_json_and_markdown(tmp_path):
    home = tmp_path / "hermes-private-root"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: test\n", encoding="utf-8")
    json_result = run_cli("quick", "--hermes-home", str(home), "--json")
    md_result = run_cli("quick", "--hermes-home", str(home), "--markdown")
    assert str(home) not in json_result.stdout
    assert str(home) not in md_result.stdout
    assert "[REDACTED_PATH]/hermes-private-root" in json_result.stdout
    assert "[REDACTED_PATH]/hermes-private-root" in md_result.stdout


def test_profiles_path_as_file_returns_finding_not_traceback(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: test\n", encoding="utf-8")
    (home / "profiles").write_text("not a directory\n", encoding="utf-8")
    result = run_cli("quick", "--hermes-home", str(home), "--json", "--fail-on", "fail")
    assert result.returncode == 2
    data = json.loads(result.stdout)
    findings = [f for c in data["checks"] for f in c["findings"]]
    assert any(f["id"] == "profiles.path_not_directory" for f in findings)


def test_fail_on_unknown_for_empty_home(tmp_path):
    home = tmp_path / "empty-hermes"
    home.mkdir()
    result = run_cli("discover", "--hermes-home", str(home), "--fail-on", "unknown")
    assert result.returncode == 1
    assert "profiles.none_detected" in result.stdout
