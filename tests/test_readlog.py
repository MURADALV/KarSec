import subprocess

def test_readlog_output():
    result = subprocess.run(
        ["python3", "-m", "karsec", "--readlog", "logs/ornek.log"],
        capture_output=True, text=True
    )
    assert "ERROR" in result.stdout
