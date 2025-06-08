import argparse
import logging
import sys
import pyfiglet

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
    logging.info("KarSec started")


if __name__ == "__main__":
    main()

