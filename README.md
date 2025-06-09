# KarSec

KarSec, Linux tabanlı bir siber güvenlik aracıdır. Komut satırından çalışarak log dosyalarını analiz etmenizi sağlar.

## Özellikler
- `--version`: Versiyon bilgisini gösterir
- `--logfile`: Analiz edilecek log dosyası
- `--readlog`: Log dosyasını okuyarak "ERROR" içeren satırları gösterir
- `--watch`: Log dosyasına eklenen satırları anlık olarak terminale yazar
- `--filter`: --readlog ile birlikte kullanıldığında, sadece verilen kelimeyi içeren satırları gösterir
- `--detect-ddos`: Log dosyasında TCP ve SYN içeren kayıtları IP'ye göre analiz eder
- `--summary`: Log dosyasındaki INFO, WARNING ve ERROR sayısını özetler
- `--scan-alert`: Log dosyasında nmap, masscan veya nikto içeren satırları listeler
- `--graph-summary`: Log dosyasındaki INFO, WARNING ve ERROR sayısını grafik olarak kaydeder
- `--classify`: Anahtar kelimelere göre satırları Scan, DDoS, Brute Force ve Data Exfiltration olarak sınıflandırır
- `--graph`: Filtrelenmiş log kayıtlarından portscan, brute-force ve dos kategorileri için bar grafik oluşturur
- `--save-summary`: Log dosyasındaki INFO, WARNING ve ERROR sayısını JSON dosyasına yazar
- `--auto-mode`: Tek komutla summary, detect-ddos ve scan-alert işlemlerini uygular. Çıktılar varsayılan olarak `outputs/` klasörüne `auto_summary.json`, `auto_ddos.txt` ve `auto_scan.txt` dosyalarına kaydedilir. `--output-dir` ile farklı klasör belirtilebilir.
- `--log-to-elk`: Log dosyasındaki her satırı Elasticsearch sunucusuna gönderir
- `--output-dir`: Otomatik mod çıktılarının kaydedileceği klasör (varsayılan: `outputs/`)

## Kurulum
```bash
git clone https://github.com/MURADALV/KarSec.git
cd KarSec
pip install .
Nasıl kullanırım?
karsec --version
karsec --logfile logs/test.log --readlog
karsec --logfile logs/test.log --detect-ddos
karsec --logfile logs/test.log --summary
karsec --logfile logs/test.log --save-summary summary.json
karsec --logfile logs/test.log --scan-alert
karsec --logfile logs/test.log --classify
karsec --logfile logs/test.log --auto-mode --output-dir results
Test nasıl yapılır?
pytest tests/

