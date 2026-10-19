from __future__ import annotations

import subprocess
import sys

import pytest

from agent_security_evals import cli


def test_cli_reports_subprocess_error_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_manifest", lambda _path: object())

    def fail_run(**_kwargs: object) -> None:
        raise subprocess.CalledProcessError(17, ["worker"])

    monkeypatch.setattr(cli, "run_adapter", fail_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-security-evals",
            "run",
            "smoke",
            "--adapter",
            "_self-test",
            "--output",
            "run",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "returned non-zero exit status 17" in captured.err
    assert "Traceback" not in captured.err
