# Port Scanner

Утилита для сканирования портов с поддержкой многопоточности.

## Компиляция

```bash
g++ -std=c++17 -o port_scanner main.cpp -pthread
```

## Использование

```bash
./port_scanner [опции]
```

### Опции

- `-h, --host <hostname>` — хост для сканирования (по умолчанию: localhost). Можно указать несколько раз
- `-f, --file <filename>` — файл со списком хостов (каждый хост на новой строке)
- `-s, --start <port>` — начальный порт (по умолчанию: 1)
- `-e, --end <port>` — конечный порт (по умолчанию: 1024)
- `-t, --timeout <ms>` — таймаут в миллисекундах (по умолчанию: 1000)
- `-T, --threads <count>` — количество потоков (по умолчанию: 10)
- `-r, --range <start-end>` — диапазон портов (альтернатива -s и -e)
- `-v, --version` — показать версию
- `-?, --help` — показать справку

### Примеры

Сканирование localhost с портов 1 по 1024:

```bash
./port_scanner
```

Сканирование нескольких хостов через командную строку:

```bash
./port_scanner --host 192.168.1.1 --host 192.168.1.2 --host example.com
```

Сканирование хостов из файла:

```bash
./port_scanner --file hosts.txt
```

Содержимое `hosts.txt`:

```
192.168.1.1
192.168.1.2
example.com
# комментарии начинаются с #
```

Сканирование диапазона портов 1-65535 с 20 потоками:

```bash
./port_scanner --range 1-65535 --threads 20
```

Сканирование с пользовательским таймаутом:

```bash
./port_scanner --host example.com --timeout 500 --start 1 --end 1000
```

Комбинированный пример:

```bash
./port_scanner --host 192.168.1.1 --file servers.txt --range 1-1024 --threads 15
```

## Как это работает

1. Программа принимает список хостов через командную строку или файл
2. Создаёт пул из N рабочих потоков (по умолчанию 10)
3. Для каждого хоста сканируются все порты из указанного диапазона
4. Каждый поток забирает пару (хост, порт) из очереди и пытается установить TCP-соединение
5. При успешном соединении порт считается открытым
6. Для каждого порта определяется служба по номеру (FTP, SSH, HTTP и т.д.)
7. Прогресс-бар показывает общий процент выполнения (все хосты + все порты)
8. Результаты выводятся в консоль в формате: `[<хост>] [OPEN] Port <порт> - <служба>`

## Технические детали

- Используются системные вызовы `socket()`, `connect()`, `setsockopt()` для установки таймаута
- Для разрешения имён используется `getaddrinfo()`
- Синхронизация доступа к очереди портов, результатам и выводу через mutex
- Атомарные переменные для отслеживания прогресса
- Поддержка комментариев в файлах (строки начинающиеся с `#` игнорируются)

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
