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
        "--detect-ddos",
        help="DDoS tespiti yapilacak log dosyasi"
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
    if args.readlog:
        try:
            with open(args.readlog, encoding="utf-8") as f:
                for line in f:
                    if "ERROR" in line:
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
    logging.info("KarSec started")


if __name__ == "__main__":
    main()

