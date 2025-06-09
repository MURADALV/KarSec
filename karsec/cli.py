import argparse
import logging
import sys
import pyfiglet
import re
import json
import urllib.request
import os
import time

import questionary

from . import __version__


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog="karsec",
        usage="%(prog)s [OPTION ...]",
        description=f"KarSec v{__version__} - simple log analysis tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    basic = parser.add_argument_group("Basic options")
    basic.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show program's version number and exit",
    )
    basic.add_argument(
        "-l",
        "--logfile",
        metavar="FILE",
        help="path to log file used by other commands",
    )
    basic.add_argument(
        "-W",
        "--watch",
        action="store_true",
        help="monitor the log file and print new lines as they appear",
    )

    analysis = parser.add_argument_group("Analysis options")
    analysis.add_argument(
        "-r",
        "--readlog",
        action="store_true",
        help="print lines containing ERROR from the log file",
    )
    analysis.add_argument(
        "-f",
        "--filter",
        metavar="WORD",
        help="with --readlog, only show lines containing WORD",
    )
    analysis.add_argument(
        "-d",
        "--detect-ddos",
        action="store_true",
        help="analyze the log file for possible DDoS activity",
    )
    analysis.add_argument(
        "-s",
        "--summary",
        action="store_true",
        help="Show summary (counts of INFO, WARNING, ERROR)",
    )
    analysis.add_argument(
        "-S",
        "--scan-alert",
        action="store_true",
        help="Detect scan-related alerts (Nmap, Masscan, etc.)",
    )
    analysis.add_argument(
        "-g",
        "--graph-summary",
        metavar="OUT",
        help="Plot bar graph of log severity counts to OUT",
    )
    analysis.add_argument(
        "-G",
        "--graph",
        action="store_true",
        help="show bar chart for filtered log categories",
    )
    analysis.add_argument(
        "-w",
        "--save-summary",
        metavar="OUT",
        help="Save summary output to a JSON file",
    )
    analysis.add_argument(
        "-a",
        "--auto-mode",
        action="store_true",
        help="Run all analyses sequentially",
    )
    analysis.add_argument(
        "--output-dir",
        default="outputs",
        metavar="DIR",
        help="directory for files created by auto mode",
    )

    ui = parser.add_argument_group("Interface options")
    ui.add_argument(
        "--menu",
        "--gui",
        action="store_true",
        dest="menu",
        help="show interactive menu",
    )

    export = parser.add_argument_group("Export options")
    export.add_argument(
        "-e",
        "--log-to-elk",
        action="store_true",
        help="send each JSON line from the log file to Elasticsearch",
    )

    return parser.parse_args(args)


def print_banner():
    banner = pyfiglet.figlet_format("KarSec")
    print(banner.rstrip())
    print("KarSec - Ağ Trafiği Analiz Aracı")
    print("by Murad Allahverdiyev")


def summarize_lines(lines):
    """Return counts of INFO, WARNING and ERROR entries."""
    counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
    for line in lines:
        upper = line.upper()
        if "INFO" in upper:
            counts["INFO"] += 1
        if "WARNING" in upper:
            counts["WARNING"] += 1
        if "ERROR" in upper:
            counts["ERROR"] += 1
    return counts


def detect_ddos_lines(lines):
    """Return dictionary of IPs suspected for DDoS based on SYN count."""
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    counts = {}
    for line in lines:
        if "TCP" in line and "SYN" in line:
            for ip in ip_pattern.findall(line):
                counts[ip] = counts.get(ip, 0) + 1
    return {ip: count for ip, count in counts.items() if count > 100}


def scan_alert_lines(lines):
    """Return list of lines that contain common scan tool keywords."""
    keywords = ("nmap", "masscan", "nikto")
    alerts = []
    for lineno, line in enumerate(lines, 1):
        lower = line.lower()
        if any(keyword in lower for keyword in keywords):
            alerts.append(f"{lineno}: {line.rstrip()}")
    return alerts


def generate_summary_chart(counts, out_path):
    """Generate a bar chart for the summary if matplotlib is available."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return False

    labels = ["INFO", "WARNING", "ERROR"]
    values = [counts.get(l, 0) for l in labels]
    colors = ["blue", "orange", "red"]

    plt.figure(figsize=(8, 6))
    plt.bar(labels, values, color=colors)
    plt.title("Log Ozeti")
    plt.xlabel("Seviye")
    plt.ylabel("Adet")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    return True


def generate_category_chart(lines, out_path="graph_output.png"):
    """Generate a bar chart for filtered log categories."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return False

    categories = ["portscan", "brute-force", "dos"]
    counts = {c: 0 for c in categories}
    for line in lines:
        lower = line.lower()
        for cat in categories:
            if cat in lower:
                counts[cat] += 1

    if not any(counts.values()):
        return False

    plt.figure(figsize=(8, 6))
    plt.bar(categories, [counts[c] for c in categories], color=["blue", "orange", "red"])
    plt.title("Log Kategorileri")
    plt.xlabel("Kategori")
    plt.ylabel("Adet")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.show()
    plt.close()
    return True


def run_summary(log_file):
    try:
        with open(log_file, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return
    print(
        f"INFO: {counts['INFO']} WARNING: {counts['WARNING']} ERROR: {counts['ERROR']}"
    )


def run_detect_ddos(log_file):
    try:
        with open(log_file, encoding="utf-8") as f:
            ddos_ips = detect_ddos_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return
    for ip, count in ddos_ips.items():
        print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")


def run_scan_alert(log_file):
    try:
        with open(log_file, encoding="utf-8") as f:
            alerts = scan_alert_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return
    for line in alerts:
        print(line)


def run_graph_summary(log_file, out_path="summary_graph.png"):
    try:
        with open(log_file, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return
    if generate_summary_chart(counts, out_path):
        print(f"Grafik kaydedildi: {out_path}")


def run_save_summary(log_file, out_path):
    try:
        with open(log_file, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return
    with open(out_path, "w", encoding="utf-8") as out_f:
        json.dump(counts, out_f)


def run_auto_mode(log_file, out_dir="outputs"):
    try:
        with open(log_file, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
        return

    os.makedirs(out_dir, exist_ok=True)
    counts = summarize_lines(lines)
    print(
        f"INFO: {counts['INFO']} WARNING: {counts['WARNING']} ERROR: {counts['ERROR']}"
    )
    ddos_ips = detect_ddos_lines(lines)
    for ip, count in ddos_ips.items():
        print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")
    alerts = scan_alert_lines(lines)
    for line in alerts:
        print(line)
    summary_path = os.path.join(out_dir, "summary_output.json")
    with open(summary_path, "w", encoding="utf-8") as out_f:
        json.dump(counts, out_f)
    chart_path = os.path.join(out_dir, "summary_chart.png")
    if generate_summary_chart(counts, chart_path):
        print(f"Grafik kaydedildi: {chart_path}")


def summary_analysis(log_path):
    """Print a summary of INFO/WARNING/ERROR counts."""
    try:
        with open(log_path, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
        sys.exit(1)
    print(
        f"INFO: {counts['INFO']} WARNING: {counts['WARNING']} ERROR: {counts['ERROR']}"
    )
    return counts


def detect_scan_alerts(log_path):
    """Print lines containing common scanning tool keywords."""
    try:
        with open(log_path, encoding="utf-8") as f:
            alerts = scan_alert_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
        sys.exit(1)
    for line in alerts:
        print(line)
    return alerts


def plot_graph(log_path, out_path="summary_graph.png"):
    """Generate and save a summary bar chart."""
    try:
        with open(log_path, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
        sys.exit(1)
    if generate_summary_chart(counts, out_path):
        print(f"Grafik kaydedildi: {out_path}")


def save_summary(log_path, out_path):
    """Save summary counts to a JSON file."""
    try:
        with open(log_path, encoding="utf-8") as f:
            counts = summarize_lines(f)
    except FileNotFoundError:
        print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
        sys.exit(1)
    with open(out_path, "w", encoding="utf-8") as out_f:
        json.dump(counts, out_f)
    return counts


def auto_mode_flow(log_path):
    """Run all basic analyses in sequence."""
    summary_analysis(log_path)
    detect_scan_alerts(log_path)
    save_summary(log_path, "summary.json")
    plot_graph(log_path)


def interactive_menu():
    choice = questionary.select(
        "Select an option:",
        choices=[
            "Show Summary",
            "Detect DDoS",
            "Scan Alert",
            "Graph Summary",
            "Save Summary to JSON",
            "Auto Mode",
        ],
    ).ask()

    if choice == "Show Summary":
        log = questionary.text("Log file path:").ask()
        if log:
            summary_analysis(log)
    elif choice == "Detect DDoS":
        log = questionary.text("Log file path:").ask()
        if log:
            run_detect_ddos(log)
    elif choice == "Scan Alert":
        log = questionary.text("Log file path:").ask()
        if log:
            detect_scan_alerts(log)
    elif choice == "Graph Summary":
        log = questionary.text("Log file path:").ask()
        out = questionary.text("Output image path (summary_graph.png):").ask()
        if log:
            plot_graph(log, out or "summary_graph.png")
    elif choice == "Save Summary to JSON":
        log = questionary.text("Log file path:").ask()
        out = questionary.text("Output JSON path:").ask()
        if log and out:
            save_summary(log, out)
    elif choice == "Auto Mode":
        log = questionary.text("Log file path:").ask()
        out_dir = questionary.text("Output directory (outputs):").ask()
        if log:
            auto_mode_flow(log)


def main(argv=None):
    print_banner()
    args = parse_args(argv)
    log_file = args.logfile
    if args.watch:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        try:
            with open(log_file, encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        print(line.rstrip("\n"), flush=True)
                    else:
                        time.sleep(0.5)
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            pass
        return
    if args.menu:
        interactive_menu()
        return
    if args.log_to_elk:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as e:
                        print(f"JSON hatasi: {e}", file=sys.stderr)
                        continue
                    try:
                        req = urllib.request.Request(
                            "http://localhost:9200/logs/_doc",
                            data=json.dumps(data).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                        )
                        with urllib.request.urlopen(req) as resp:
                            resp.read()
                    except Exception as e:
                        print(f"Elasticsearch hatasi: {e}", file=sys.stderr)
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
            sys.exit(1)
    if args.auto_mode:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        auto_mode_flow(log_file)
        return
    if args.readlog:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        filtered_lines = []
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    if args.filter:
                        if args.filter in line:
                            print(line.rstrip("\n"))
                            filtered_lines.append(line.rstrip("\n"))
                    elif "ERROR" in line:
                        print(line.rstrip("\n"))
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
            sys.exit(1)
        if args.graph and args.filter and filtered_lines:
            if generate_category_chart(filtered_lines, "graph_output.png"):
                print("Grafik kaydedildi: graph_output.png")
    if args.detect_ddos:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        counts = {}
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    if "TCP" in line and "SYN" in line:
                        for ip in ip_pattern.findall(line):
                            counts[ip] = counts.get(ip, 0) + 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_file}", file=sys.stderr)
            sys.exit(1)
        for ip, count in counts.items():
            if count > 100:
                print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")
    if args.scan_alert:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        detect_scan_alerts(log_file)
    if args.graph_summary:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        out_path = args.graph_summary
        plot_graph(log_file, out_path)
    if args.save_summary:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        out_path = args.save_summary
        save_summary(log_file, out_path)
    if args.summary:
        if not log_file:
            print("Log dosyasi belirtilmedi", file=sys.stderr)
            sys.exit(1)
        summary_analysis(log_file)
    logging.info("KarSec started")


if __name__ == "__main__":
    main()
