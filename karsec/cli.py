import argparse
import logging
import sys
import pyfiglet
import re

from . import __version__


def parse_args(args=None):
    parser = argparse.ArgumentParser(prog="karsec", description="KarSec CLI")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--logfile",
        help="Yazılacak log dosyasının yolu"
    )
    parser.add_argument(
        "--readlog",
        help="Okunacak log dosyasının yolu"
    )
    parser.add_argument(
        "--filter",
        help="--readlog ile birlikte kullanildiginda sadece bu kelimeyi iceren satirlari goster"
    )
    parser.add_argument(
        "--detect-ddos",
        help="DDoS tespiti yapilacak log dosyasi"
    )
    parser.add_argument(
        "--summary",
        help="Log dosyasindaki INFO, WARNING ve ERROR sayilarini ozetler"
    )
    parser.add_argument(
        "--scan-alert",
        help="Log dosyasinda nmap, masscan veya nikto iceren satirlari goster"
    )
    parser.add_argument(
        "--graph-summary",
        help="Log dosyasindaki INFO, WARNING ve ERROR sayilarini grafik olarak goster"
    )
    parser.add_argument(
        "--auto-mode",
        help="Summary, detect-ddos ve scan-alert islemlerini tek seferde calistir"
    )
    return parser.parse_args(args)


def print_banner():
    banner = pyfiglet.figlet_format("KarSec")
    print(banner.rstrip())
    print("KarSec - Ağ Trafiği Analiz Aracı")
    print("by Murad Allahverdiyev")


def main(argv=None):
    print_banner()
    args = parse_args(argv)
    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.INFO)
    if args.auto_mode:
        try:
            with open(args.auto_mode, encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.auto_mode}", file=sys.stderr)
            sys.exit(1)
        summary_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        for line in lines:
            upper = line.upper()
            if "INFO" in upper:
                summary_counts["INFO"] += 1
            if "WARNING" in upper:
                summary_counts["WARNING"] += 1
            if "ERROR" in upper:
                summary_counts["ERROR"] += 1
        print(
            f"INFO: {summary_counts['INFO']} WARNING: {summary_counts['WARNING']} ERROR: {summary_counts['ERROR']}"
        )
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        counts = {}
        for line in lines:
            if "TCP" in line and "SYN" in line:
                for ip in ip_pattern.findall(line):
                    counts[ip] = counts.get(ip, 0) + 1
        for ip, count in counts.items():
            if count > 100:
                print(f"DDoS \u015f\u00fcpheli IP: {ip} - {count}")
        keywords = ("nmap", "masscan", "nikto")
        for lineno, line in enumerate(lines, 1):
            lower = line.lower()
            if any(keyword in lower for keyword in keywords):
                print(f"{lineno}: {line.rstrip('\n')}")
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
        summary_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        try:
            with open(args.graph_summary, encoding="utf-8") as f:
                for line in f:
                    upper = line.upper()
                    if "INFO" in upper:
                        summary_counts["INFO"] += 1
                    if "WARNING" in upper:
                        summary_counts["WARNING"] += 1
                    if "ERROR" in upper:
                        summary_counts["ERROR"] += 1
        except FileNotFoundError:
            print(f"Dosya bulunamadi: {args.graph_summary}", file=sys.stderr)
            sys.exit(1)
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = ["INFO", "WARNING", "ERROR"]
        values = [summary_counts[l] for l in labels]
        colors = ["blue", "orange", "red"]

        plt.bar(labels, values, color=colors)
        plt.title("Log Ozeti")
        plt.xlabel("Seviye")
        plt.ylabel("Adet")
        plt.tight_layout()
        plt.show()
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

