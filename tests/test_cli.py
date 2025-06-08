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


def test_parse_detect_ddos():
    args = parse_args(["--detect-ddos", "ddos.log"])
    assert args.detect_ddos == "ddos.log"


def test_parse_summary():
    args = parse_args(["--summary", "some.log"])
    assert args.summary == "some.log"


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
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[-1].strip() == f"karsec {__version__}"
    assert result.returncode == 0


def test_readlog_output(capsys):
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "ornek.log"))
    main(["--readlog", log_path])
    captured = capsys.readouterr()
    error_lines = [line for line in captured.out.strip().splitlines() if "ERROR" in line]
    assert len(error_lines) == 2
    assert all("ERROR" in line for line in error_lines)


def test_readlog_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--readlog", "nonexistent.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_summary_output(capsys, tmp_path):
    log_file = tmp_path / "summary.log"
    log_file.write_text("""INFO start\nWARNING watch\nERROR fail\nINFO end\n""", encoding="utf-8")
    main(["--summary", str(log_file)])
    captured = capsys.readouterr()
    assert "INFO: 2" in captured.out
    assert "WARNING: 1" in captured.out
    assert "ERROR: 1" in captured.out


def test_summary_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--summary", "missing.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_banner_display(capsys):
    main([])
    captured = capsys.readouterr()
    assert "KarSec - Ağ Trafiği Analiz Aracı" in captured.out
    assert "by Murad Allahverdiyev" in captured.out


def test_detect_ddos_output(capsys):
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "ddos.log"))
    main(["--detect-ddos", log_path])
    captured = capsys.readouterr()
    assert "DDoS" in captured.out


