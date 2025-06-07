import argparse
import re


def extract_ddos_entries(log_file):
    """Yield lines from log_file that appear to be related to DDoS attacks."""
    ddos_pattern = re.compile(r"ddos", re.IGNORECASE)
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            if ddos_pattern.search(line):
                yield line.rstrip("\n")


def main():
    parser = argparse.ArgumentParser(description="Extract DDoS records from a log file")
    parser.add_argument("log", nargs="?", default="log.txt", help="Path to the log file (default: log.txt)")
    args = parser.parse_args()

    for entry in extract_ddos_entries(args.log):
        print(entry)


if __name__ == "__main__":
    main()
