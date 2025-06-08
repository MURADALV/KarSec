# KarSec

KarSec, Linux tabanlı bir siber güvenlik aracıdır. Komut satırından çalışarak log dosyalarını analiz etmenizi sağlar.

## Özellikler
- `--version`: Versiyon bilgisini gösterir
- `--logfile`: Belirtilen dosyaya log kaydı başlatır
- `--readlog`: Log dosyasını okuyarak "ERROR" içeren satırları gösterir
- `--detect-ddos`: Log dosyasında TCP ve SYN içeren kayıtları IP'ye göre analiz eder

## Kurulum
```bash
git clone https://github.com/MURADALV/KarSec.git
cd KarSec
pip install .
Nasıl kullanırım?
karsec --version
karsec --logfile logs/test.log
karsec --readlog logs/test.log
karsec --detect-ddos logs/ddos.log
Test nasıl yapılır?
pytest tests/

