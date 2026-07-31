# Port Scanner v2.0 (MVP)

Утилита для пентеста с поддержкой SYN scan, version detection, banner grabbing и экспорта в JSON.

## Возможности

- **TCP Connect Scan** — стандартное сканирование через connect()
- **SYN Scan** — stealth сканирование через raw sockets (требует root/CAP_NET_RAW)
- **UDP Scan** — сканирование UDP портов
- **Version Detection** — определение версий сервисов (SSH, FTP, SMTP, HTTP, Memcached и др.)
- **Banner Grabbing** — захват баннеров сервисов
- **SSL/TLS Detection** — автоматическое определение SSL портов
- **Exploit Checks** — проверка на known уязвимости (Heartbleed, Shellshock, Ghostscript, PoleCache)
- **Rate Limiting** — ограничение скорости пакетов для обхода IDS/IPS
- **JSON Export** — экспорт результатов в JSON (без внешних зависимостей)
- **Presets** — готовые профили сканирования (--quick, --stealth, --vuln, --full)
- **Graceful Degradation** — автоматический fallback на connect scan если SYN недоступен
- **Multi-threaded** — высокопроизводительное многопоточное сканирование

## Компиляция

### Shared library для C API:

```bash
g++ -std=c++17 -shared -fPIC -o libport_scanner.so port_scanner.cpp -pthread
```

### CLI версия (через C API):

```bash
g++ -std=c++17 -o port_scanner_cli port_scanner_cli.cpp -L. -lport_scanner -pthread
```

### Standalone версия (main.cpp):

```bash
g++ -std=c++17 -o port_scanner main.cpp -L. -lport_scanner -pthread
```

**Примечание:** Standalone версия (`main.cpp`) — это полноценный executable, который линкуется с `libport_scanner.so` и поддерживает все те же опции, что и `port_scanner_cli`. Отличается тем, что скомпилирована как отдельный бинарный файл без зависимости от CLI парсера.

## Использование

Сканировщик доступен в двух версиях:

1. **port_scanner_cli** — версия через C API (рекомендуется)
2. **port_scanner** — standalone executable

Обе версии поддерживают **одинаковые опции и флаги**.

### Базовое использование

```bash
# CLI версия
./port_scanner_cli [опции]

# Standalone версия
./port_scanner [опции]
```

### Основные опции

- `-h, --host <hostname>` — хост для сканирования (по умолчанию: localhost). Можно указать несколько раз
- `-f, --file <filename>` — файл со списком хостов (каждый хост на новой строке)
- `-s, --start <port>` — начальный порт (по умолчанию: 1)
- `-e, --end <port>` — конечный порт (по умолчанию: 1024)
- `-t, --timeout <ms>` — таймаут в миллисекундах (по умолчанию: 1000)
- `-T, --threads <count>` — количество потоков (по умолчанию: 10)
- `-r, --range <start-end>` — диапазон портов (альтернатива -s и -e)

### Новые опции (v2.0)

#### Типы сканирования
- `--syn` — SYN scan вместо connect scan (требует root/CAP_NET_RAW)
- `--udp` — UDP сканирование
- `-t, --timeout <ms>` — таймаут в миллисекундах (по умолчанию: 1000)
- `-T, --threads <count>` — количество потоков (по умолчанию: 10)
- `--rate-limit <n>` — ограничение скорости в пакетах/сек (по умолчанию: без ограничений)

#### Дополнительные функции
- `--version-detect` — включить определение версий сервисов
- `--banner-grab` — включить захват баннеров
- `--exploit <name>` — проверка уязвимостей: `heartbleed`, `shellshock`, `ghostscript`, `polecache`
- `--json <file>` — экспорт результатов в JSON файл

#### Пресеты сканирования

| Пресет | Описание | Диапазон портов | Тип сканирования |
|--------|----------|-----------------|------------------|
| `--quick` | Быстрое сканирование | 1–100 | TCP Connect |
| `--stealth` | Stealth сканирование | 1–1024 | SYN |
| `--vuln` | Проверка уязвимостей | 1–1024 | TCP Connect + version detection |
| `--full` | Полный скан | 1–65535 | SYN + UDP + version + banner |
| `--all-scans` | Все функции | пользовательский | SYN + version + banner |

### Примеры использования пресетов

```bash
# Быстрое сканирование (топ-100 портов)
./port_scanner_cli --quick --host 192.168.1.1

# Stealth сканирование (SYN scan, топ-1024 портов)
sudo ./port_scanner_cli --stealth --host 192.168.1.1

# Проверка уязвимостей
sudo ./port_scanner_cli --vuln --host example.com --range 1-1024

# Полный скан всех портов
sudo ./port_scanner_cli --full --host target.com

# С проверкой конкретной уязвимости
sudo ./port_scanner_cli --exploit heartbleed --host example.com --range 443-443
```

### SYN Scan

SYN scan (также известный как "half-open scanning") — это более эффективный и менее заметный метод сканирования по сравнению с полным TCP подключением.

**Принцип работы:**
1. Отправляется TCP SYN пакет (запрос на установку соединения)
2. Если порт открыт — целевой сервер отвечает SYN+ACK, сканер отправляет RST и разрывает соединение, не завершая 3-этапное рукопожатие
3. Если порт закрыт — сервер отвечает RST
4. Если межсетевой экран фильтрует — таймаут

**Преимущества SYN scan:**
- **Stealth**: не завершает TCP соединение, менее заметен в логах
- **Скорость**: не требуется ожидание полного установления соединения
- **Эффективность**: можно сканировать больше портов за единицу времени

**Требования:**
- **root** или Capability `CAP_NET_RAW` (Linux)
- На macOS raw sockets работают иначе — автоматический fallback на connect scan

**Использование:**

```bash
# Базовый SYN scan (требует sudo)
sudo ./port_scanner_cli --syn --host 192.168.1.1 --range 1-1024

# SYN scan с определением версий сервисов
sudo ./port_scanner_cli --syn --version-detect --host example.com --range 1-1024

# SYN scan со всеми проверками (version + banner grabbing)
sudo ./port_scanner_cli --syn --all-scans --host target.com --range 1-65535

# SYN scan с экспортом результатов
sudo ./port_scanner_cli --syn --version-detect --banner-grab --json report.json --host target.com
```

**Fallback на Connect Scan:**
Если у процесса нет прав на использование raw sockets, программа автоматически переключается на connect scan и выводит предупреждение:
```
[WARN] Raw sockets unavailable (need root/CAP_NET_RAW). Falling back to connect scan for target.com
```

### UDP Scan

UDP сканирование проверяет открытость UDP портов, которые не сканируются стандартным TCP scan.

**Принцип работы:**
1. Отправляется пустой UDP пакет на целевой порт
2. Если получен ICMP port unreachable — порт закрыт
3. Если получен ответ или таймаут — порт может быть открыт

**Особенности:**
- Значительно медленнее TCP scan (из-за необходимости ждать ответов)
- По умолчанию conservative: таймаут считается как закрытый порт
- Рекомендуется для проверки DNS (53), NTP (123), SNMP (161), DHCP (67/68)

**Использование:**

```bash
# UDP сканирование ключевых портов
./port_scanner_cli --udp --host 192.168.1.1 --range 53-53,123-123,161-161

# UDP scan с version detection
./port_scanner_cli --udp --version-detect --host dns-server --range 53-53

# Полный UDP scan (медленно!)
./port_scanner_cli --udp --range 1-1024 --timeout 2000
```

### Exploit Checks

Проверка на известные уязвимости после обнаружения открытых портов.

**Поддерживаемые уязвимости:**

| Флаг | Уязвимость | CVE | Порт по умолчанию |
|------|-----------|-----|-------------------|
| `heartbleed` | Heartbleed Bug | CVE-2014-0160 | 443 |
| `shellshock` | Bash Remote Code Execution | CVE-2014-6271 | 80, 443 |
| `ghostscript` | Ghostscript RCE | CVE-2018-16509 | - |
| `polecache` | Memcached Unauthorized Access | - | 11211 |

**Использование:**

```bash
# Проверка на Heartbleed
sudo ./port_scanner_cli --exploit heartbleed --host example.com --range 443-443

# Проверка на Shellshock
sudo ./port_scanner_cli --exploit shellshock --host example.com --range 80-80

# Сканирование Memcached на PoleCache
./port_scanner_cli --exploit polecache --host 192.168.1.1 --range 11211-11211

# В сочетании с --vuln пресетом
sudo ./port_scanner_cli --vuln --exploit heartbleed --host target.com --range 443-443
```

### Rate Limiting

Ограничение скорости отправки пакетов для обхода IDS/IPS.

```bash
# Ограничение до 100 пакетов в секунду
./port_scanner_cli --rate-limit 100 --host target.com --range 1-1024

# Aggressive scan (1000 pkt/s)
sudo ./port_scanner_cli --rate-limit 1000 --host target.com --range 1-65535

# Stealth mode (10 pkt/s)
sudo ./port_scanner_cli --syn --rate-limit 10 --host target.com --range 1-1024
```

### Примеры

Базовое сканирование:
```bash
./port_scanner_cli
./port_scanner_cli --host 192.168.1.1 --host 192.168.1.2
./port_scanner_cli --file hosts.txt
```

SYN scan с определением версий:
```bash
sudo ./port_scanner_cli --syn --version-detect --host example.com
```

Полный скан с экспортом в JSON:
```bash
sudo ./port_scanner_cli --all-scans --json report.json --host 192.168.1.1 --range 1-1024
```

UDP сканирование:
```bash
# Проверка DNS сервера
./port_scanner_cli --udp --host 8.8.8.8 --range 53-53

# UDP scan ключевых сервисов
./port_scanner_cli --udp --host 192.168.1.1 --range 53-53,123-123,161-161,11211-11211
```

Комбинированные сканы:
```bash
# SYN + version detection + rate limiting
sudo ./port_scanner_cli --syn --version-detect --rate-limit 50 --host target.com --range 1-1024

# Full scan с экспортом в JSON
sudo ./port_scanner_cli --full --json full-report.json --host target.com

# Проверка уязвимостей с экспортом
sudo ./port_scanner_cli --vuln --exploit heartbleed --json vuln-report.json --host target.com --range 443-443
```

Пресеты:
```bash
# Быстрый скан
./port_scanner_cli --quick --host target.com

# Stealth
sudo ./port_scanner_cli --stealth --host target.com

# Проверка уязвимостей
sudo ./port_scanner_cli --vuln --host target.com

# Полный скан
sudo ./port_scanner_cli --full --host target.com
```

## Как это работает

### TCP Connect Scan
1. Программа создаёт TCP сокет и пытается установить полное соединение с портом
2. При успехе — порт открыт, при ошибке — закрыт или недоступен

### SYN Scan ( Stealth )
1. Создаётся raw socket для отправки пакетов на уровне IP
2. Отправляется TCP SYN пакет с случайным source port
3. Ответы:
   - **SYN+ACK** → порт открыт, отправляется RST для разрыва (stealth)
   - **RST** → порт закрыт
   - **ICMP error** → порт недоступен/filtered
4. **Graceful Degradation**: если raw sockets недоступны (нет root), автоматически переключается на connect scan

### Version Detection

Для каждого открытого порта отправляется protocol-specific probe, ответ парсится и извлекается версия сервиса. Результаты кэшируются по ключу `(host:port)`.

Поддерживаемые протоколы:

| Порт  | Протокол     | Метод                                          | Примеры версий                          |
|-------|-------------|------------------------------------------------|-----------------------------------------|
| 21    | FTP         | Команда `FEAT` (RFC 2389), парсинг 220 banner  | `vsFTPd 3.0.3`, `ProFTPD 1.3.5`        |
| 22    | SSH         | Отправка `SSH-2.0-PortScanner`, парсинг ответа | `OpenSSH_8.9p1`, `OpenSSH_7.4p1`       |
| 23    | Telnet      | IAC negotiation (RFC 854)                      | `Debian-4.6`, `FreeBSD Telnet`, `NetKit` |
| 25    | SMTP        | Команда `EHLO`, парсинг 220 banner             | `Postfix`, `Exim`, `Microsoft ESMTP`, `Sendmail` |
| 80    | HTTP        | `HEAD /` запрос, парсинг Server/X-Powered-By   | `nginx/1.18.0`, `Apache/2.4.41`, `Microsoft-IIS/10.0` |
| 443   | HTTPS       | TLS ClientHello + SNI, парсинг сертификата     | `nginx`, `Apache`, `TLS`               |
| 3306  | MySQL       | MySQL init packet, парсинг handshake response  | `5.7.34`, `8.0.26`, `10.5.12-MariaDB`  |
| 5432  | PostgreSQL  | PostgreSQL startup message v3.0                | `PostgreSQL 13.4`, `PostgreSQL 14.2`   |
| 11211 | Memcached   | Команда `version`                              | `1.6.17`, `1.5.6`                      |
| —     | Default     | Чтение автоматического баннера (1-я строка)    | Первые 1024 байта баннера              |

### Banner Grabbing

1. Подключение к открытому порту
2. **SSL/TLS детекция** — для портов 443, 993, 995, 465, 587, 8443:
   - Отправка TLS ClientHello с SNI
   - Извлечение сертификата: Subject CN, Organization
   - Проверки: `EXPIRED`, `SELF-SIGNED`, `WEAK KEY`
   - Пример: `SSL/TLS cert: CN=example.com | .SSL...Handshake...`
3. **HTTP пробы** — если нет автоматического баннера, отправляется `GET / HTTP/1.0`
4. Возврат первой строки баннера или полного баннера (до 2048 байт)

**Примеры баннеров:**
```
SSH-2.0-OpenSSH_8.9p1
220 (vsFTPd 3.0.3) Ready
HTTP/1.1 200 OK
SSL/TLS cert: CN=example.com [SELF-SIGNED]
```

### Экспорт в JSON

Функция `scanner_export_json()` сериализует все результаты сканирования в формат JSON без внешних зависимостей.

#### Пример JSON вывода:

```json
{
  "scan_info": {
    "scan_type": "connect",
    "port_range": "27015-27020",
    "timestamp": "2026-07-31T20:42:54Z",
    "scan_options": {
      "version_detection": true,
      "banner_grabbing": true
    }
  },
  "hosts": [
    {
      "address": "127.0.0.1",
      "status": "online",
      "ports": [
        {
          "port": 27017,
          "protocol": "tcp",
          "state": "open",
          "service": "MongoDB",
          "version": "MongoDB",
          "banner": null,
          "ssl": false,
          "vulnerabilities": []
        }
      ]
    }
  ],
  "summary": {
    "total_hosts": 1,
    "online_hosts": 1,
    "total_open_ports": 1,
    "vulnerable_ports": 0
  }
}
```

#### Поля JSON:

**scan_info:**
- `scan_type` — тип сканирования: `"syn"` или `"connect"`
- `port_range` — диапазон портов, например `"1-1024"`
- `timestamp` — время сканирования в ISO 8601 формате
- `scan_options` — включённые опции (`version_detection`, `banner_grabbing`)

**hosts:**
- `address` — IP адрес или hostname
- `status` — `"online"` (есть открытые порты), `"no-open-ports"` (хост жив, но портов нет), `"offline"`
- `ports` — массив результатов для каждого отсканированного порта

**ports:**
- `port` — номер порта
- `protocol` — `"tcp"`
- `state` — `"open"`, `"closed"`, `"open|filtered"` (UDP)
- `service` — название службы (SSH, HTTP, MongoDB и т.д.)
- `version` — версия сервиса (если определена)
- `banner` — захваченный баннер
- `ssl` — `true` если SSL/TLS детектирован
- `vulnerabilities` — массив найденных уязвимостей (заглушка для будущих эксплойт-чеков)

**summary:**
- `total_hosts` — всего хостов
- `online_hosts` — доступных хостов
- `total_open_ports` — открытых портов
- `vulnerable_ports` — уязвимых портов

#### Использование из CLI:

```bash
# Экспорт в JSON файл
./port_scanner_cli --host 192.168.1.1 --range 1-1024 --json report.json

# Полный скан с экспортом
./port_scanner_cli --all-scans --host target.com --range 1-65535 --json full-report.json
```

#### Использование из Dart/Flutter:

```dart
// Получение JSON из C API
String getJsonResults(ScannerWrapper scanner) {
  Pointer<Utf8> jsonPtr = scanner_export_json(scanner);
  String json = jsonPtr.toDartString();
  scanner_free_json(jsonPtr);
  return json;
}

// Парсинг JSON
Map<String, dynamic> parseResults(String jsonStr) {
  return jsonDecode(jsonStr);
}

// Пример: обработка результатов
void processResults(ScannerWrapper scanner) {
  String jsonStr = getJsonResults(scanner);
  Map<String, dynamic> data = parseResults(jsonStr);
  
  // Доступ к данным
  var scanInfo = data['scan_info'];
  print("Scan type: ${scanInfo['scan_type']}");
  print("Timestamp: ${scanInfo['timestamp']}");
  
  var hosts = data['hosts'] as List;
  for (var host in hosts) {
    print("Host: ${host['address']} (${host['status']})");
    var ports = host['ports'] as List;
    for (var port in ports) {
      if (port['state'] == 'open') {
        print("  Open: ${port['port']}/${port['protocol']} "
              "(${port['service']}) "
              "${port['version'] != null ? '[${port['version']}]' : ''}");
      }
    }
  }
  
  var summary = data['summary'];
  print("Total: ${summary['total_open_ports']} open ports, "
        "${summary['online_hosts']} hosts online");
}
```

## Технические детали

### Сканирование

- **SYN Scan**: raw sockets (IPPROTO_TCP), manual TCP header construction, RFC 793 checksum, stealth mode
- **Connect Scan**: standard socket()+connect() with SO_RCVTIMEO/SO_SNDTIMEO
- **UDP Scan**: datagram sockets (IPPROTO_UDP), ICMP error analysis
- **Graceful Degradation**: автоматический fallback на connect scan при отсутствии root/CAP_NET_RAW
- **Port Detection**: TCP SYN/RST analysis, ICMP error handling (type 3, code 3 = port unreachable)
- **Rate Limiting**: configurable packets per second for IDS evasion

### Version Detection

- **Protocol-specific probes**: FTP (FEAT), SSH (SSH-2.0), Telnet (IAC negotiation), HTTP (HEAD), SMTP (EHLO), MySQL (init packet), PostgreSQL (startup message), Memcached (version), HTTPS (TLS ClientHello)
- **Caching**: результаты кешируются по ключу `(host:port)` для повторных сканирований
- **Service Recognition**: автоматическое определение vsFTPd, ProFTPD, OpenSSH, Postfix, Exim, nginx, Apache, MongoDB, PostgreSQL и др.

### Banner Grabbing

- **SSL/TLS Detection**: автоматическая детекция для портов 443, 993, 995, 465, 587, 8443
- **Certificate Analysis**: извлечение Subject CN, Organization из TLS handshake
- **Security Checks**: проверка на expired, self-signed, weak key (RSA 1024/512)
- **HTTP Probing**: fallback для HTTP портов — отправка `GET / HTTP/1.0` при отсутствии баннера

### JSON Export

- **Zero Dependencies**: ручная сериализация, никаких внешних библиотек
- **Proper Escaping**: экранирование control characters (unicode), quotes, backslashes
- **Optional Fields**: version и banner выводятся как `null` если не определены
- **Sorted Output**: порты в JSON отсортированы по номеру

### Архитектура

- **Thread Safety**: mutex для очереди, результатов, вывода; atomic для прогресса
- **Work Queue**: worker threads с atomic counter completed tasks
- **Multi-platform**: macOS compatible (FFI для Flutter), Android NDK ready

### Собираемые файлы

```
port_scanner/
├── port_scanner.h          # C API header
├── port_scanner.cpp        # Core library (scan, version, banner, JSON)
├── port_scanner_cli.cpp    # CLI с парсингом аргументов
├── main.cpp                # Standalone executable
├── libport_scanner.so      # Shared library (Linux/Android)
└── readme.md               # Документация
```

## Полное руководство по использованию

### Быстрый старт

```bash
# Сборка
g++ -std=c++17 -o port_scanner main.cpp -L. -lport_scanner -pthread

# Простое сканирование localhost
./port_scanner

# Сканирование конкретного хоста
./port_scanner --host 192.168.1.1

# Сканирование диапазона портов
./port_scanner --host target.com --range 1-1024
```

### Все команды CLI

```bash
# Быстрый скан топ-100 портов (connect scan)
./port_scanner_cli --start 1 --end 100

# Полноценный stealth скан
sudo ./port_scanner_cli --syn --host target.com --range 1-1024

# Полный скан со всеми проверками
sudo ./port_scanner_cli --all-scans --host target.com --range 1-65535

# Сканирование с экспортом в JSON
./port_scanner_cli --host 192.168.1.1 --range 1-1024 --json report.json

# Сканирование файла хостов
./port_scanner_cli --file hosts.txt --range 1-1024

# Настройки производительности
./port_scanner_cli --host target.com --range 1-1024 --timeout 500 --threads 20
```

### Использование C API

```c
#include <stdio.h>
#include <stdlib.h>
#include "port_scanner.h"

int main() {
    // 1. Создаём сканер
    const char* hosts[] = {"192.168.1.1", "192.168.1.2"};
    ScannerWrapper* scanner = scanner_create(
        hosts, 2,    // 2 хоста
        1, 1024,    // порт range
        1000,       // timeout 1000ms
        10          // max threads
    );
    
    if (!scanner) {
        fprintf(stderr, "Failed to create scanner\n");
        return 1;
    }
    
    // 2. Настраиваем опции
    scanner_set_scan_type(scanner, SCAN_TYPE_CONNECT);
    scanner_set_enable_version_detection(scanner, 1);
    scanner_set_enable_banner_grabbing(scanner, 1);
    
    // 3. Запускаем сканирование
    scanner_scan(scanner);
    
    // 4. Получаем результаты
    int count = scanner_get_result_count(scanner);
    for (int i = 0; i < count; i++) {
        PortResult r = scanner_get_result(scanner, i);
        if (r.is_open) {
            printf("OPEN: %s port %d (%s)",
                   r.host, r.port, r.service);
            if (r.version) printf(" [%s]", r.version);
            if (r.banner) printf(" | %s", r.banner);
            printf("\n");
        }
    }
    
    // 5. Экспортируем в JSON
    char* json = scanner_export_json(scanner);
    FILE* f = fopen("report.json", "w");
    fwrite(json, 1, strlen(json), f);
    fclose(f);
    scanner_free_json(json);
    
    // 6. Освобождаем ресурсы
    scanner_destroy(scanner);
    
    // 7. Освобождаем память результатов
    for (int i = 0; i < count; i++) {
        PortResult r = scanner_get_result(scanner, i);
        free(r.host);
        free(r.service);
        free(r.version);
        free(r.banner);
    }
    
    return 0;
}
```

### Типичные сценарии

#### 1. Разведка сети

```bash
# Сканирование всей подсети /24 (топ порты)
for i in {1..254}; do echo "192.168.1.$i"; done > hosts.txt
./port_scanner_cli --file hosts.txt --range 1-1024 --json network-scan.json
```

#### 2. Проверка веб-серверов

```bash
# Сканирование HTTP/HTTPS на популярных хостах
./port_scanner_cli --host example.com --host test.com \
  --range 80-80,443-443 --version-detect --banner-grab
```

#### 3. Pentest сценарий

```bash
# Stealth скан с версиями и баннерами
sudo ./port_scanner_cli --syn --all-scans --host target.com \
  --range 1-65535 --json pentest-report.json
```

#### 4. Мониторинг сервисов

```bash
# Периодическая проверка critical портов
./port_scanner_cli --host db-server \
  --range 3306-3306,5432-5432,6379-6379 \
  --timeout 200
```

### Производительность

```bash
# Для больших сетей — увеличиваем потоки, уменьшаем таймаут
./port_scanner_cli --host target.com --range 1-65535 \
  --timeout 300 --threads 50

# Для stealth сканирования — уменьшаем скорость
sudo ./port_scanner_cli --syn --host target.com --range 1-65535 \
  --timeout 2000 --threads 5
```

### Troubleshooting

**Проблема**: SYN scan не работает, fallback на connect scan
```
[WARN] Raw sockets unavailable (need root/CAP_NET_RAW). Falling back...
```
**Решение**: Запустите с `sudo` или добавьте capability:
```bash
sudo setcap cap_net_raw+ep ./port_scanner_cli
```

**Проблема**: Медленное сканирование
**Решение**: Уменьшите timeout или увеличьте threads:
```bash
./port_scanner_cli --host target.com --range 1-65535 --timeout 200 --threads 50
```

**Проблема**: Нет версий сервисов
**Решение**: Убедитесь, что включена version detection и сервис отвечает на probes:
```bash
./port_scanner_cli --host target.com --range 22-22,80-80 --version-detect
```

### Android разрешения

Для работы на Android добавьте разрешение в `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Без этого разрешения приложение не сможет устанавливать сетевые соединения для сканирования портов.

## Использование в Flutter

Для использования порт-сканера в Flutter-приложениях доступен C API, который можно вызывать через FFI.

### Сборка shared library для macOS

```bash
g++ -std=c++17 -shared -fPIC -o libport_scanner.dylib port_scanner.cpp -pthread
```

### Сборка shared library для Android

Для Android требуется NDK. Примеры сборки для различных архитектур:

**arm64-v8a:**
```bash
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang++ \
  -std=c++17 -shared -fPIC \
  -o libport_scanner_arm64-v8a.so \
  port_scanner.cpp \
  -pthread
```

**armeabi-v7a:**
```bash
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang++ \
  -std=c++17 -shared -fPIC \
  -o libport_scanner_armeabi-v7a.so \
  port_scanner.cpp \
  -pthread
```

Рекомендуется настроить CMakeLists.txt для автоматической сборки под все целевые архитектуры.

### Dart API (через FFI)

```dart
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

final DynamicLibrary _lib = Platform.isAndroid
    ? DynamicLibrary.open('libport_scanner.so')
    : DynamicLibrary.open('libport_scanner.dylib');

typedef ScannerCreateFn = Pointer<ScannerWrapper> Function(
    Pointer<Pointer<Utf8>> hosts, Int32 hostsCount,
    Int32 startPort, Int32 endPort,
    Int32 timeoutMs, Int32 maxThreads);
typedef ScannerCreate = Pointer<ScannerWrapper> Function(
    Pointer<Pointer<Utf8>> hosts, Int32 hostsCount,
    Int32 startPort, Int32 endPort,
    Int32 timeoutMs, Int32 maxThreads);

typedef ScannerDestroyFn = Void Function(Pointer<ScannerWrapper> scanner);
typedef ScannerDestroy = Void Function(Pointer<ScannerWrapper> scanner);

typedef ScannerScanFn = Void Function(Pointer<ScannerWrapper> scanner);
typedef ScannerScan = Void Function(Pointer<ScannerWrapper> scanner);

typedef ScannerGetResultCountFn = Int32 Function(Pointer<ScannerWrapper> scanner);
typedef ScannerGetResultCount = Int32 Function(Pointer<ScannerWrapper> scanner);

typedef ScannerGetResultFn = PortResult Function(Pointer<ScannerWrapper> scanner, Int32 index);
typedef ScannerGetResult = PortResult Function(Pointer<ScannerWrapper> scanner, Int32 index);

typedef ScannerGetHostStatusFn = HostStatus Function(Pointer<ScannerWrapper> scanner, Int32 index);
typedef ScannerGetHostStatus = HostStatus Function(Pointer<ScannerWrapper> scanner, Int32 index);

final scannerCreate = _lib.lookupFunction<ScannerCreateFn, ScannerCreate>('scanner_create');
final scannerDestroy = _lib.lookupFunction<ScannerDestroyFn, ScannerDestroy>('scanner_destroy');
final scannerScan = _lib.lookupFunction<ScannerScanFn, ScannerScan>('scanner_scan');
final scannerGetResultCount = _lib.lookupFunction<ScannerGetResultCountFn, ScannerGetResultCount>('scanner_get_result_count');
final scannerGetResult = _lib.lookupFunction<ScannerGetResultFn, ScannerGetResult>('scanner_get_result');
final scannerGetHostStatus = _lib.lookupFunction<ScannerGetHostStatusFn, ScannerGetHostStatus>('scanner_get_host_status');

@ ffi struct
class HostStatus extends ffi.Struct {
  external int value;
}

@ffi.struct
class PortResult extends ffi.Struct {
  external Pointer<ffi.Char> host;
  external int port;
  external int is_open;
  external Pointer<ffi.Char> service;
}

Future<List<Map<String, dynamic>>> scanPorts({
  required List<String> hosts,
  int startPort = 1,
  int endPort = 1024,
  int timeoutMs = 1000,
  int maxThreads = 10,
}) async {
  final hostArray = hosts.map((h) => h.toNativeUtf8()).toList();
  final hostPtr = allocate<Pointer<Utf8>>(count: hosts.length);
  
  for (int i = 0; i < hosts.length; i++) {
    hostPtr[i] = hostArray[i];
  }

  final scanner = scannerCreate(
    hostPtr,
    hosts.length.toInt(),
    startPort.toInt(),
    endPort.toInt(),
    timeoutMs.toInt(),
    maxThreads.toInt(),
  );

  if (scanner == nullptr) {
    for (final h in hostArray) {
      free(h);
    }
    free(hostPtr);
    throw Exception('Failed to create scanner');
  }

  scannerScan(scanner);

  final results = <Map<String, dynamic>>[];
  final resultCount = scannerGetResultCount(scanner);

  for (int i = 0; i < resultCount; i++) {
    final result = scannerGetResult(scanner, i);
    results.add({
      'host': result.host.toDartString(),
      'port': result.port,
      'is_open': result.is_open == 1,
      'service': result.service.toDartString(),
    });
    free(result.host);
    free(result.service);
  }

  final hostStatusCount = hosts.length;
  final hostStatuses = <String, String>{};

  for (int i = 0; i < hostStatusCount; i++) {
    final status = scannerGetHostStatus(scanner, i);
    final statusStr = status.value == 0
        ? 'ONLINE'
        : status.value == 1
            ? 'NO_PORTS'
            : 'OFFLINE';
    hostStatuses[hosts[i]] = statusStr;
  }

  scannerDestroy(scanner);

  for (final h in hostArray) {
    free(h);
  }
  free(hostPtr);

  return {
    'results': results,
    'hostStatuses': hostStatuses,
  };
}
```

### C API функции

В `port_scanner.h` определены следующие функции:

```c
// Создание и уничтожение сканера
ScannerWrapper* scanner_create(const char* hosts[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads);
void scanner_destroy(ScannerWrapper* scanner);

// Сканирование
void scanner_scan(ScannerWrapper* scanner);

// Настройки (вызываются ДО scanner_scan)
void scanner_set_scan_type(ScannerWrapper* scanner, ScanType type);
void scanner_set_exploit_check(ScannerWrapper* scanner, ExploitCheck check);
void scanner_set_enable_version_detection(ScannerWrapper* scanner, int enable);
void scanner_set_enable_banner_grabbing(ScannerWrapper* scanner, int enable);
void scanner_set_rate_limit(ScannerWrapper* scanner, int packets_per_sec);

// Получение результатов
int scanner_get_result_count(ScannerWrapper* scanner);
PortResult scanner_get_result(ScannerWrapper* scanner, int index);
HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index);

// Экспорт
char* scanner_export_json(ScannerWrapper* scanner);
ScanReport* scanner_get_report(ScannerWrapper* scanner);
void scanner_free_report(ScanReport* report);
void scanner_free_json(char* json);
```

### Типы данных

**HostStatus** — перечисление статусов хоста:
- `HOST_STATUS_ONLINE = 0` — хост доступен, найдены открытые порты
- `HOST_STATUS_NO_PORTS = 1` — хост доступен, но открытых портов не найдено
- `HOST_STATUS_OFFLINE = 2` — хост недоступен

**ScanType** — тип сканирования:
- `SCAN_TYPE_SYN = 0` — stealth SYN scan (требует root)
- `SCAN_TYPE_CONNECT = 1` — стандартный TCP connect scan
- `SCAN_TYPE_UDP = 2` — UDP scan

**ExploitCheck** — проверка уязвимостей:
- `EXPLOIT_NONE = 0` — без проверки
- `EXPLOIT_HEARTBLEED = 1` — CVE-2014-0160 (OpenSSL)
- `EXPLOIT_SHELLSHOCK = 2` — CVE-2014-6271 (Bash)
- `EXPLOIT_GHOSTSCRIPT = 3` — Ghostscript
- `EXPLOIT_POLECACHE = 4` — PoleCache

**PortResult** — структура результата сканирования порта:
```c
typedef struct {
    char* host;      // Имя хоста (выделяется память, требуется free)
    int port;        // Номер порта
    int is_open;     // 1 если порт открыт, 0 если закрыт
    int is_udp;      // 1 если UDP порт
    char* service;   // Название службы (выделяется память, требуется free)
    char* version;   // Версия сервиса (может быть NULL)
    char* banner;    // Баннер сервиса (может быть NULL)
    int ssl;         // 1 если SSL/TLS детектирован
} PortResult;
```

## Риски и платформы

### 1. SYN scan требует root/CAP_NET_RAW (Linux)
**Риск:** SYN scan использует raw sockets, которые требуют прав root или capability `CAP_NET_RAW`.

**Смягчение:** Реализован graceful fallback — если raw sockets недоступны, автоматически переключается на connect scan с предупреждением:
```
[WARN] Raw sockets unavailable (need root/CAP_NET_RAW). Falling back to connect scan for target.com
```

**Решение:**
```bash
# Вариант 1: Запуск через sudo
sudo ./port_scanner_cli --syn --host target.com

# Вариант 2: Добавление capability (рекомендуется)
sudo setcap cap_net_raw+ep ./port_scanner_cli
```

### 2. macOS raw sockets (SO_CONNECT_TIME fallback)
**Риск:** На macOS raw sockets работают иначе и требуют повышенных привилегий.

**Смягчение:** На macOS автоматически используется `SO_CONNECT_TIME` fallback — socket option, который позволяет определить открытость порта без raw sockets:
- Используется non-blocking connect + select()
- Проверяется `SO_CONNECT_TIME` для определения результата
- Fallback прозрачен для пользователя

**Особенности:**
- Требует macOS 10.4+
- Менее точен чем raw socket SYN scan
- Автоматически активируется при отсутствии прав

### 3. UDP сканирование медленное
**Риск:** UDP scan значительно медленнее TCP из-за необходимости ждать ответов или таймаутов.

**Смягчение:**
- Предупреждение при сканировании >1024 портов
- Ошибка при попытке сканирования всех 65535 UDP портов
- Рекомендуется ограничивать диапазон портов

**Рекомендации:**
```bash
# ✅ Рекомендуемый диапазон (до 1024 портов)
./port_scanner_cli --udp --host target.com --range 1-1024

# ✅ Ключевые UDP порты
./port_scanner_cli --udp --host dns-server --range 53-53,123-123,161-161

# ❌ Не рекомендуется (медленно!)
./port_scanner_cli --udp --host target.com --range 1-65535
# Ошибка: UDP scan of all 65535 ports is not recommended
```

### 4. JSON без внешних зависимостей
**Риск:** Зависимости от внешних библиотек усложняют билд для Android/iOS.

**Смягчение:** Ручная сериализация JSON (~150 строк) без внешних зависимостей:
- Все контрольные символы экранируются
- Поддержка unicode через `\uXXXX`
- Optional поля (version, banner) выводятся как `null`
- Можно добавить nlohmann/json позже для расширенного функционала

### 5. Android/iOS ABI compatibility
**Риск:** Изменение структуры C API ломает совместимость с существующими приложениями.

**Смягчение:**
- C API использует `extern "C"` — нет name mangling
- `ScannerWrapper` — opaque struct (forward declaration)
- Новые поля добавляются в конец структур (`ssl` в PortResult)
- Enums имеют фиксированные значения
- Stable ABI для Dart FFI

**Пример стабильного API:**
```c
// Эти функции не меняют сигнатуру при добавлении новых опций
ScannerWrapper* scanner_create(...);
void scanner_destroy(ScannerWrapper*);
void scanner_scan(ScannerWrapper*);
char* scanner_export_json(ScannerWrapper*);
```

