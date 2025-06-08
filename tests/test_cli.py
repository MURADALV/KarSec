import sys
import subprocess
import os
import time
import json

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


def test_parse_watch():
    args = parse_args(["--watch", "watch.log"])
    assert args.watch == "watch.log"


def test_parse_detect_ddos():
    args = parse_args(["--detect-ddos", "ddos.log"])
    assert args.detect_ddos == "ddos.log"


def test_parse_summary():
    args = parse_args(["--summary", "some.log"])
    assert args.summary == "some.log"


def test_parse_graph_summary():
    args = parse_args(["--graph-summary", "some.log"])
    assert args.graph_summary == ["some.log"]

    args = parse_args(["--graph-summary", "some.log", "out.png"])
    assert args.graph_summary == ["some.log", "out.png"]


def test_parse_graph():
    args = parse_args(["--graph"])
    assert args.graph


def test_parse_save_summary():
    args = parse_args(["--save-summary", "in.log", "out.json"])
    assert args.save_summary == ["in.log", "out.json"]


def test_parse_auto_mode():
    args = parse_args(["--auto-mode", "log.log"])
    assert args.auto_mode == "log.log"


def test_parse_output_dir():
    args = parse_args(["--output-dir", "out"])
    assert args.output_dir == "out"


def test_parse_log_to_elk():
    args = parse_args(["--log-to-elk", "elk.log"])
    assert args.log_to_elk == "elk.log"


def test_parse_filter():
    args = parse_args(["--filter", "first"])
    assert args.filter == "first"


def test_short_option_aliases():
    assert parse_args(["-l", "log.log"]).logfile == "log.log"
    assert parse_args(["-r", "read.log"]).readlog == "read.log"
    assert parse_args(["-W", "watch.log"]).watch == "watch.log"
    assert parse_args(["-f", "term"]).filter == "term"
    assert parse_args(["-d", "ddos.log"]).detect_ddos == "ddos.log"
    assert parse_args(["-s", "sum.log"]).summary == "sum.log"
    assert parse_args(["-S", "scan.log"]).scan_alert == "scan.log"
    assert parse_args(["-G"]).graph
    assert parse_args(["-w", "in.log", "out.json"]).save_summary == ["in.log", "out.json"]
    assert parse_args(["-a", "auto.log"]).auto_mode == "auto.log"
    assert parse_args(["-e", "elk.log"]).log_to_elk == "elk.log"


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


def test_readlog_filter_output(capsys):
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "ornek.log"))
    main(["--readlog", log_path, "--filter", "first"])
    captured = capsys.readouterr()
    lines = [line for line in captured.out.strip().splitlines() if "first" in line]
    assert len(lines) == 1


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


def test_save_summary_output(tmp_path):
    log_file = tmp_path / "save.log"
    out_file = tmp_path / "summary.json"
    log_file.write_text("INFO a\nWARNING b\nERROR c\nINFO d\n", encoding="utf-8")
    main(["--save-summary", str(log_file), str(out_file)])
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data == {"INFO": 2, "WARNING": 1, "ERROR": 1}


def test_save_summary_file_not_found(capsys, tmp_path):
    out_file = tmp_path / "out.json"
    with pytest.raises(SystemExit) as exc:
        main(["--save-summary", "missing.log", str(out_file)])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_graph_summary_output(capsys, tmp_path):
    log_file = tmp_path / "graph.log"
    log_file.write_text("INFO x\nWARNING y\nERROR z\nINFO a\n", encoding="utf-8")
    out_file = tmp_path / "out.png"
    main(["--graph-summary", str(log_file), str(out_file)])
    captured = capsys.readouterr()
    assert captured.err == ""
    assert out_file.exists()
    assert "Grafik kaydedildi" in captured.out


def test_graph_summary_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--graph-summary", "yok.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_graph_output(tmp_path, capsys):
    log_file = tmp_path / "graph.log"
    log_file.write_text(
        "attack portscan\nattack brute-force\nattack dos\n", encoding="utf-8"
    )
    main(["--readlog", str(log_file), "--filter", "attack", "--graph"])
    captured = capsys.readouterr()
    assert "Grafik kaydedildi" in captured.out
    assert os.path.exists("graph_output.png")
    os.remove("graph_output.png")


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


def test_parse_scan_alert():
    args = parse_args(["--scan-alert", "scan.log"])
    assert args.scan_alert == "scan.log"


def test_scan_alert_output(capsys, tmp_path):
    log_file = tmp_path / "scan.log"
    log_file.write_text("Nmap taramasi\nNormal satir\nnikto test\n", encoding="utf-8")
    main(["--scan-alert", str(log_file)])
    captured = capsys.readouterr()
    out_lines = captured.out.strip().splitlines()
    assert any("1: Nmap taramasi" in line for line in out_lines)
    assert any("3: nikto test" in line for line in out_lines)


def test_scan_alert_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--scan-alert", "yok.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_log_to_elk_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--log-to-elk", "missing.log"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_auto_mode_output(tmp_path, capsys):
    log_file = tmp_path / "auto.log"
    lines = [f"192.168.1.1 TCP SYN {i}\n" for i in range(101)]
    log_file.write_text(
        "INFO start\nWARNING watch\nERROR fail\nINFO end\n" + "".join(lines) + "nmap scan\n",
        encoding="utf-8",
    )
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        main(["--auto-mode", str(log_file)])
    finally:
        os.chdir(cwd)
    captured = capsys.readouterr()
    summary_data = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary_data == {"INFO": 2, "WARNING": 1, "ERROR": 1}
    assert (tmp_path / "summary_graph.png").exists()
    assert "nmap scan" in captured.out.lower()


def test_watch_output(tmp_path):
    log_file = tmp_path / "watch.log"
    log_file.write_text("", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "karsec", "--watch", str(log_file)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(0.5)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("hello\n")
        time.sleep(0.5)
    finally:
        proc.terminate()
    out, _ = proc.communicate(timeout=2)
    assert "hello" in out


