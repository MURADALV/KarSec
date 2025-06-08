import argparse
import logging
import sys
import pyfiglet
import re
import json
import urllib.request
import os
import time

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
        help="write log messages to FILE",
    )
    basic.add_argument(
        "-W",
        "--watch",
        metavar="FILE",
        help="monitor FILE and print new lines as they appear",
    )

    analysis = parser.add_argument_group("Analysis options")
    analysis.add_argument(
        "-r",
        "--readlog",
        metavar="FILE",
        help="read FILE and print lines containing ERROR",
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
        metavar="FILE",
        help="analyze FILE for possible DDoS activity",
    )
    analysis.add_argument(
        "-s",
        "--summary",
        metavar="FILE",
        help="summarize INFO/WARNING/ERROR counts in FILE",
    )
    analysis.add_argument(
        "-a",
        "--scan-alert",
        metavar="FILE",
        help="list lines mentioning nmap, masscan or nikto",
    )
    analysis.add_argument(
        "-g",
        "--graph-summary",
        nargs="+",
        metavar=("LOG", "OUT"),
        help="save a bar chart for LOG summary to OUT (default: summary_graph.png)",
    )
    analysis.add_argument(
        "-w",
        "--save-summary",
        nargs=2,
        metavar=("LOG", "OUT"),
        help="write INFO/WARNING/ERROR counts from LOG to JSON file OUT",
    )
    analysis.add_argument(
        "-A",
        "--auto-mode",
        metavar="FILE",
        help="run summary, detect-ddos and scan-alert on FILE",
    )
    analysis.add_argument(
        "--output-dir",
        default="outputs",
        metavar="DIR",
        help="directory for files created by auto mode",
    )

    export = parser.add_argument_group("Export options")
    export.add_argument(
        "-e",
        "--log-to-elk",
        metavar="FILE",
        help="send each JSON line from FILE to Elasticsearch",
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


def main(argv=None):
    print_banner()
    args = parse_args(argv)
    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.INFO)
    if args.watch:
        try:
            with open(args.watch, encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        print(line.rstrip("\n"), flush=True)
                    else:
                        time.sleep(0.5)
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.watch}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            pass
        return
    if args.log_to_elk:
        try:
            with open(args.log_to_elk, encoding="utf-8") as f:
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
            print(f"Dosya bulunamadi: {args.log_to_elk}", file=sys.stderr)
            sys.exit(1)
    if args.auto_mode:
        try:
            with open(args.auto_mode, encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.auto_mode}", file=sys.stderr)
            sys.exit(1)

        out_dir = args.output_dir if args.output_dir else "outputs"
        os.makedirs(out_dir, exist_ok=True)

        summary_counts = summarize_lines(lines)
        print(
            f"INFO: {summary_counts['INFO']} WARNING: {summary_counts['WARNING']} ERROR: {summary_counts['ERROR']}"
        )
        print("[\u2713] Log summary completed.")

        ddos_ips = detect_ddos_lines(lines)
        for ip, count in ddos_ips.items():
            print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")
        print("[\u2713] DDoS analysis completed.")

        scan_lines = scan_alert_lines(lines)
        for entry in scan_lines:
            print(entry)
        print("[\u2713] Scan alert check completed.")

        summary_path = os.path.join(out_dir, "summary_output.json")
        with open(summary_path, "w", encoding="utf-8") as out_f:
            json.dump(summary_counts, out_f)
        print(f"[\u2713] Summary saved: {summary_path}")

        chart_path = os.path.join(out_dir, "summary_chart.png")
        if generate_summary_chart(summary_counts, chart_path):
            print(f"[\u2713] Summary chart saved: {chart_path}")
        return
    if args.readlog:
        try:
            with open(args.readlog, encoding="utf-8") as f:
                for line in f:
                    if args.filter:
                        if args.filter in line:
                            print(line.rstrip("\n"))
                    elif "ERROR" in line:
                        print(line.rstrip("\n"))
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.readlog}", file=sys.stderr)
            sys.exit(1)
    if args.detect_ddos:
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        counts = {}
        try:
            with open(args.detect_ddos, encoding="utf-8") as f:
                for line in f:
                    if "TCP" in line and "SYN" in line:
                        for ip in ip_pattern.findall(line):
                            counts[ip] = counts.get(ip, 0) + 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.detect_ddos}", file=sys.stderr)
            sys.exit(1)
        for ip, count in counts.items():
            if count > 100:
                print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")
    if args.scan_alert:
        keywords = ("nmap", "masscan", "nikto")
        try:
            with open(args.scan_alert, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    lower = line.lower()
                    if any(keyword in lower for keyword in keywords):
                        print(f"{lineno}: {line.rstrip('\n')}")
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.scan_alert}", file=sys.stderr)
            sys.exit(1)
    if args.graph_summary:
        # The first parameter is the log file. The second one, if provided,
        # denotes the output image path.
        log_path = args.graph_summary[0]
        out_path = (
            args.graph_summary[1]
            if len(args.graph_summary) > 1
            else "summary_graph.png"
        )

        summary_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    upper = line.upper()
                    if "INFO" in upper:
                        summary_counts["INFO"] += 1
                    if "WARNING" in upper:
                        summary_counts["WARNING"] += 1
                    if "ERROR" in upper:
                        summary_counts["ERROR"] += 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
            sys.exit(1)
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = ["INFO", "WARNING", "ERROR"]
        values = [summary_counts[l] for l in labels]
        colors = ["blue", "orange", "red"]

        # Prepare a clear and informative graph
        plt.figure(figsize=(8, 6))
        plt.bar(labels, values, color=colors)
        plt.title("Log Ozeti")
        plt.xlabel("Seviye")
        plt.ylabel("Adet")
        plt.tight_layout()

        # Save the plot instead of displaying it
        plt.savefig(out_path)
        plt.close()
        print(f"Grafik kaydedildi: {out_path}")
    if args.save_summary:
        log_path, out_path = args.save_summary
        summary_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    upper = line.upper()
                    if "INFO" in upper:
                        summary_counts["INFO"] += 1
                    if "WARNING" in upper:
                        summary_counts["WARNING"] += 1
                    if "ERROR" in upper:
                        summary_counts["ERROR"] += 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {log_path}", file=sys.stderr)
            sys.exit(1)
        with open(out_path, "w", encoding="utf-8") as out_f:
            json.dump(summary_counts, out_f)

    if args.summary:
        summary_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        try:
            with open(args.summary, encoding="utf-8") as f:
                for line in f:
                    upper = line.upper()
                    if "INFO" in upper:
                        summary_counts["INFO"] += 1
                    if "WARNING" in upper:
                        summary_counts["WARNING"] += 1
                    if "ERROR" in upper:
                        summary_counts["ERROR"] += 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.summary}", file=sys.stderr)
            sys.exit(1)
        print(
            f"INFO: {summary_counts['INFO']} WARNING: {summary_counts['WARNING']} ERROR: {summary_counts['ERROR']}"
        )
    logging.info("KarSec started")


if __name__ == "__main__":
    main()
