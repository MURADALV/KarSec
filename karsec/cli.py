import argparse
import logging

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
    return parser.parse_args(args)


def main(argv=None):
    args = parse_args(argv)
    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.INFO)
    logging.info("KarSec started")


if __name__ == "__main__":
    main()

