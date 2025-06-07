import sys
import subprocess
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from karsec import __version__
from karsec.cli import parse_args, main


def test_parse_logfile():
    args = parse_args(["--logfile", "test.log"])
    assert args.logfile == "test.log"


def test_parse_readlog():
    args = parse_args(["--readlog", "example.log"])
    assert args.readlog == "example.log"


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


def test_readlog_output(capsys):
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "ornek.log"))
    main(["--readlog", log_path])
    captured = capsys.readouterr()
    lines = [line for line in captured.out.strip().splitlines() if line]
    assert len(lines) == 2
    assert all("ERROR" in line for line in lines)


def test_readlog_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--readlog", "nonexistent.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


