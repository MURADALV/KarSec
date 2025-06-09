import sys
import subprocess
import os
import time
import json
import base64

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from karsec import __version__
from karsec.cli import parse_args, main


def test_parse_logfile():
    args = parse_args(["--logfile", "test.log"])
    assert args.logfile == "test.log"


def test_parse_readlog():
    args = parse_args(["--readlog"])
    assert args.readlog


def test_parse_watch():
    args = parse_args(["--watch"])
    assert args.watch


def test_parse_live():
    args = parse_args(["--live"])
    assert args.live


def test_parse_detect_ddos():
    args = parse_args(["--detect-ddos"])
    assert args.detect_ddos


def test_parse_summary():
    args = parse_args(["--summary"])
    assert args.summary


def test_parse_graph_summary():
    args = parse_args(["--graph-summary", "out.png"])
    assert args.graph_summary == "out.png"


def test_parse_graph():
    args = parse_args(["--graph"])
    assert args.graph


def test_parse_save_summary():
    args = parse_args(["--save-summary", "out.json"])
    assert args.save_summary == "out.json"


def test_parse_auto_mode():
    args = parse_args(["--auto-mode"])
    assert args.auto_mode


def test_parse_output_dir():
    args = parse_args(["--output-dir", "out"])
    assert args.output_dir == "out"


def test_parse_log_to_elk():
    args = parse_args(["--log-to-elk"])
    assert args.log_to_elk


def test_parse_filter():
    args = parse_args(["--filter", "first"])
    assert args.filter == "first"


def test_parse_report():
    args = parse_args(["--report"])
    assert args.report


def test_parse_classify():
    args = parse_args(["--classify"])
    assert args.classify


def test_parse_predict():
    args = parse_args(["--predict"])
    assert args.predict


def test_short_option_aliases():
    assert parse_args(["-l", "log.log"]).logfile == "log.log"
    assert parse_args(["-r"]).readlog
    assert parse_args(["-w"]).watch
    assert parse_args(["-f", "term"]).filter == "term"
    assert parse_args(["-dd"]).detect_ddos
    assert parse_args(["-s"]).summary
    assert parse_args(["-sa"]).scan_alert
    assert parse_args(["-G"]).graph
    assert parse_args(["-sS", "out.json"]).save_summary == "out.json"
    assert parse_args(["-a"]).auto_mode
    assert parse_args(["-e"]).log_to_elk


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
    main(["--logfile", log_path, "--readlog"])
    captured = capsys.readouterr()
    error_lines = [line for line in captured.out.strip().splitlines() if "ERROR" in line]
    assert len(error_lines) == 2
    assert all("ERROR" in line for line in error_lines)


def test_readlog_filter_output(capsys):
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "ornek.log"))
    main(["--logfile", log_path, "--readlog", "--filter", "first"])
    captured = capsys.readouterr()
    lines = [line for line in captured.out.strip().splitlines() if "first" in line]
    assert len(lines) == 1


def test_readlog_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "nonexistent.log", "--readlog"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_summary_output(capsys, tmp_path):
    log_file = tmp_path / "summary.log"
    log_file.write_text("""INFO start\nWARNING watch\nERROR fail\nINFO end\n""", encoding="utf-8")
    main(["--logfile", str(log_file), "--summary"])
    captured = capsys.readouterr()
    assert "INFO: 2" in captured.out
    assert "WARNING: 1" in captured.out
    assert "ERROR: 1" in captured.out


def test_summary_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "missing.log", "--summary"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_save_summary_output(tmp_path):
    log_file = tmp_path / "save.log"
    out_file = tmp_path / "summary.json"
    log_file.write_text("INFO a\nWARNING b\nERROR c\nINFO d\n", encoding="utf-8")
    main(["--logfile", str(log_file), "--save-summary", str(out_file)])
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data == {"INFO": 2, "WARNING": 1, "ERROR": 1}


def test_save_summary_file_not_found(capsys, tmp_path):
    out_file = tmp_path / "out.json"
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "missing.log", "--save-summary", str(out_file)])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_graph_summary_output(capsys, tmp_path):
    log_file = tmp_path / "graph.log"
    log_file.write_text("INFO x\nWARNING y\nERROR z\nINFO a\n", encoding="utf-8")
    out_file = tmp_path / "out.png"
    main(["--logfile", str(log_file), "--graph-summary", str(out_file)])
    captured = capsys.readouterr()
    assert captured.err == ""
    assert out_file.exists()
    assert "Grafik kaydedildi" in captured.out


def test_graph_summary_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "yok.log", "--graph-summary", "out.png"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_graph_output(tmp_path, capsys):
    log_file = tmp_path / "graph.log"
    log_file.write_text(
        "attack portscan\nattack brute-force\nattack dos\n", encoding="utf-8"
    )
    main(["--logfile", str(log_file), "--readlog", "--filter", "attack", "--graph"])
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
    main(["--logfile", log_path, "--detect-ddos"])
    captured = capsys.readouterr()
    assert "DDoS" in captured.out


def test_parse_scan_alert():
    args = parse_args(["--scan-alert"])
    assert args.scan_alert


def test_scan_alert_output(capsys, tmp_path):
    log_file = tmp_path / "scan.log"
    log_file.write_text("Nmap taramasi\nNormal satir\nnikto test\n", encoding="utf-8")
    main(["--logfile", str(log_file), "--scan-alert"])
    captured = capsys.readouterr()
    out_lines = captured.out.strip().splitlines()
    assert any("1: Nmap taramasi" in line for line in out_lines)
    assert any("3: nikto test" in line for line in out_lines)


def test_scan_alert_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "yok.log", "--scan-alert"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Dosya bulunamadi" in captured.err


def test_log_to_elk_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--logfile", "missing.log", "--log-to-elk"])
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
        main(["--logfile", str(log_file), "--auto-mode"])
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
        [sys.executable, "-m", "karsec", "--logfile", str(log_file), "--watch"],
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


def test_classify_output(capsys, tmp_path):
    log_file = tmp_path / "cls.log"
    log_file.write_text(
        "nmap scan\npossible ddos syn flood\nfailed password attempt\nftp exfil\n",
        encoding="utf-8",
    )
    main(["--logfile", str(log_file), "--classify"])
    captured = capsys.readouterr()
    out_lines = captured.out.strip().splitlines()
    assert any("Scan:" in line and "1" in line for line in out_lines)
    assert any("DDoS:" in line and "1" in line for line in out_lines)
    assert any("Brute Force:" in line and "1" in line for line in out_lines)
    assert any("Data Exfiltration:" in line and "1" in line for line in out_lines)
    assert any("Toplam: 4" in line for line in out_lines)


def test_report_output(tmp_path):
    out_dir = tmp_path / "outputs"
    out_dir.mkdir()
    (out_dir / "summary_output.json").write_text(json.dumps({"INFO": 1, "WARNING": 0, "ERROR": 0}), encoding="utf-8")
    (out_dir / "classify_output.json").write_text(json.dumps({"Scan": 1}), encoding="utf-8")
    (out_dir / "ddos_ips.json").write_text(json.dumps({"192.168.1.1": 150}), encoding="utf-8")
    (out_dir / "scan_alerts.txt").write_text("1: nmap scan\n", encoding="utf-8")
    img = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII=")
    with open(out_dir / "summary_chart.png", "wb") as f:
        f.write(img)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        main(["--report"])
    finally:
        os.chdir(cwd)
    pdfs = list(out_dir.glob("karsec_raporu_*.pdf"))
    assert pdfs


def test_predict_model_missing(tmp_path, capsys):
    log_file = tmp_path / "pred.log"
    log_file.write_text("test line\n", encoding="utf-8")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        main(["--logfile", str(log_file), "--predict"])
    finally:
        os.chdir(cwd)
    captured = capsys.readouterr()
    assert "Model yuklenemedi, --predict ozelligi pasif." in captured.err


def test_predict_output(tmp_path, capsys):
    log_file = tmp_path / "pred.log"
    log_file.write_text("scan attempt\nbenign example\n", encoding="utf-8")
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    pipeline = Pipeline([
        ("vect", CountVectorizer()),
        ("clf", RandomForestClassifier(n_estimators=1, random_state=0)),
    ])
    pipeline.fit(["scan attempt", "benign example"], ["Scan", "Benign"])
    model_path = tmp_path / "model.pkl"
    joblib.dump(pipeline, model_path)

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        main(["--logfile", str(log_file), "--predict"])
    finally:
        os.chdir(cwd)
    captured = capsys.readouterr()
    out_lines = [line for line in captured.out.strip().splitlines() if line]
    assert any("Scan" in line for line in out_lines)
    assert any("Benign" in line for line in out_lines)


