import subprocess

def test_readlog_output():
    result = subprocess.run(
        ["python3", "-m", "karsec", "--logfile", "logs/ornek.log", "--readlog"],
        capture_output=True, text=True
    )
    assert "ERROR" in result.stdout


def test_readlog_filter_output_subprocess():
    result = subprocess.run(
        ["python3", "-m", "karsec", "--logfile", "logs/ornek.log", "--readlog", "--filter", "first"],
        capture_output=True, text=True
    )
    assert "first" in result.stdout
    assert "second" not in result.stdout
