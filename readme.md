# Port Scanner v2.0 (MVP)

Утилита для пентеста с поддержкой SYN scan, version detection, banner grabbing и экспорта в JSON.

## Возможности

- **TCP Connect Scan** — стандартное сканирование через connect()
- **SYN Scan** — stealth сканирование через raw sockets (требует root/CAP_NET_RAW)
- **Version Detection** — определение версий сервисов (SSH, FTP, SMTP, HTTP, Memcached и др.)
- **Banner Grabbing** — захват баннеров сервисов
- **SSL/TLS Detection** — автоматическое определение SSL портов
- **JSON Export** — экспорт результатов в JSON (без внешних зависимостей)
- **Graceful Degradation** — автоматический fallback на connect scan если SYN недоступен
- **Multi-threaded** — высокопроизводительное многопоточное сканирование

## Компиляция

### Shared library для C API:

```bash
g++ -std=c++17 -shared -fPIC -o libport_scanner.so port_scanner.cpp -pthread
```

### CLI версия:

```bash
g++ -std=c++17 -o port_scanner_cli port_scanner_cli.cpp -L. -lport_scanner -pthread
```

### Использовать main.cpp (standalone):

```bash
g++ -std=c++17 -o port_scanner main.cpp -pthread
```

## Использование CLI

```bash
./port_scanner_cli [опции]
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

- `--syn` — SYN scan вместо connect scan (требует root)
- `--version-detect` — включить определение версий сервисов
- `--banner-grab` — включить захват баннеров
- `--json <file>` — экспорт результатов в JSON файл
- `--all-scans` — включить все функции (SYN + version + banner)

### Пресеты

```bash
# Быстрое сканирование (connect scan, топ-100 портов)
./port_scanner_cli --start 1 --end 100

# Stealth сканирование (SYN scan, топ-1024 портов)
./port_scanner_cli --syn --start 1 --end 1024

# Полный скан со всеми проверками
./port_scanner_cli --all-scans --host 192.168.1.1
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
Для каждого открытого порта отправляются protocol-specific probe:
- **SSH** (22): отправка "SSH-2.0-PortScanner", парсинг ответа
- **FTP** (21): команда FEAT (RFC 2389)
- **HTTP** (80): HEAD запрос, парсинг Server header
- **SMTP** (25): EHLO команда
- **Memcached** (11211): команда "version"
- Результаты кэшируются по ключу (host:port)

### Banner Grabbing
1. Подключение к открытому порту
2. Ожидание 500ms для автоматического баннера
3. Возврат первой строки баннера (до 1024 байт)

### Экспорт в JSON
- Ручная сериализация без внешних зависимостей
- Включает scan_info, hosts (с портами, версиями, баннерами), summary
- Экранирование специальных символов в строках

## Технические детали

- **SYN Scan**: raw sockets (IPPROTO_TCP), manual TCP header construction, RFC 793 checksum
- **Connect Scan**: standard socket()+connect() with SO_RCVTIMEO/SO_SNDTIMEO
- **DNS Resolution**: getaddrinfo() with AF_INET
- **Thread Safety**: mutex для очереди, результатов, вывода; atomic для прогресса
- **Cross-platform**: macOS compatible (SO_CONNECT_TIME fallback для raw sockets)

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
ScannerWrapper* scanner_create(const char* hosts[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads);
void scanner_destroy(ScannerWrapper* scanner);
void scanner_scan(ScannerWrapper* scanner);
int scanner_get_result_count(ScannerWrapper* scanner);
PortResult scanner_get_result(ScannerWrapper* scanner, int index);
HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index);
```

### Типы данных

**HostStatus** — перечисление статусов хоста:
- `HOST_STATUS_ONLINE = 0` — хост доступен, найдены открытые порты
- `HOST_STATUS_NO_PORTS = 1` — хост доступен, но открытых портов не найдено
- `HOST_STATUS_OFFLINE = 2` — хост недоступен

**PortResult** — структура результата сканирования порта:
```c
typedef struct {
    char* host;      // Имя хоста (выделяется память, требуется free)
    int port;        // Номер порта
    int is_open;     // 1 если порт открыт, 0 если закрыт
    char* service;   // Название службы (выделяется память, требуется free)
} PortResult;
```

### Android разрешения

Для работы на Android добавьте разрешение в `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Без этого разрешения приложение не сможет устанавливать сетевые соединения для сканирования портов.
