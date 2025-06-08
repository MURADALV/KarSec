# KarSec

KarSec, Linux tabanlı bir siber güvenlik aracıdır. Komut satırından çalışarak log dosyalarını analiz etmenizi sağlar.

## Özellikler
- `--version`: Versiyon bilgisini gösterir
- `--logfile`: Belirtilen dosyaya log kaydı başlatır
- `--readlog`: Log dosyasını okuyarak "ERROR" içeren satırları gösterir
- `--watch`: Log dosyasına eklenen satırları anlık olarak terminale yazar
- `--filter`: --readlog ile birlikte kullanıldığında, sadece verilen kelimeyi içeren satırları gösterir
- `--detect-ddos`: Log dosyasında TCP ve SYN içeren kayıtları IP'ye göre analiz eder
- `--summary`: Log dosyasındaki INFO, WARNING ve ERROR sayısını özetler
- `--scan-alert`: Log dosyasında nmap, masscan veya nikto içeren satırları listeler
- `--graph-summary`: Log dosyasındaki INFO, WARNING ve ERROR sayısını grafik olarak gösterir
- `--auto-mode`: Tek komutla summary, detect-ddos ve scan-alert işlemlerini uygular
- `--log-to-elk`: Log dosyasındaki her satırı Elasticsearch sunucusuna gönderir

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
karsec --summary logs/test.log
karsec --scan-alert logs/test.log
karsec --auto-mode logs/test.log
karsec --log-to-elk logs/test.json
Test nasıl yapılır?
pytest tests/

