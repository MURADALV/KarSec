import sys
import subprocess
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from karsec import __version__
from karsec.cli import parse_args


def test_parse_logfile():
    args = parse_args(["--logfile", "test.log"])
    assert args.logfile == "test.log"


def test_version_option(capsys):
    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert f"karsec {__version__}" in captured.out


def test_cli_version_subprocess():
    result = subprocess.run(
        [sys.executable, "-m", "karsec", "--version"],
        text=True,
        capture_output=True,
    )
    assert result.stdout.strip() == f"karsec {__version__}"
    assert result.returncode == 0


