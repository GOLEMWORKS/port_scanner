import 'dart:ffi';
import 'dart:io';

// ============================================================
// Port Scanner Dart FFI Binding
// ============================================================
// 
// Usage example:
// ```dart
// import 'port_scanner_ffi.dart';
// 
// void main() async {
//   // Load library
//   final scannerLib = PortScannerLib();
//   await scannerLib.load();
//   
//   // Create scanner
//   final hosts = ['192.168.1.1', 'localhost'].toNativeUtf8Array();
//   final scanner = scannerLib.scanner_create(
//     hosts, 2, 1, 1024, 1000, 10
//   );
//   
//   // Configure
//   scannerLib.scanner_set_enable_version_detection(scanner, 1);
//   scannerLib.scanner_set_enable_banner_grabbing(scanner, 1);
//   
//   // Scan
//   scannerLib.scanner_scan(scanner);
//   
//   // Get results
//   final count = scannerLib.scanner_get_result_count(scanner);
//   for (int i = 0; i < count; i++) {
//     final result = scannerLib.scanner_get_result(scanner, i);
//     if (result.is_open == 1) {
//       print('Port ${result.port} is open (${result.service.toDartString()})');
//     }
//   }
//   
//   // Cleanup
//   scannerLib.scanner_destroy(scanner);
//   for (final h in hosts) {
//     h.dispose();
//   }
// }
// ```

// ==================== Native Structures ====================

@ffi.struct
class HostStatus extends ffi.Struct {
  @ffi.int()
  external int value;
}

@ffi.struct
class PortResult extends ffi.Struct {
  external ffi.Pointer<ffi.Char> host;
  
  @ffi.int()
  external int port;
  
  @ffi.int()
  external int is_open;
  
  @ffi.int()
  external int is_udp;
  
  external ffi.Pointer<ffi.Char> service;
  external ffi.Pointer<ffi.Char> version;
  external ffi.Pointer<ffi.Char> banner;
  
  @ffi.int()
  external int ssl;
}

@ffi.struct
class ScannerWrapper extends ffi.Opaque {}

// ==================== Function Signatures ====================

// scanner_create
typedef ScannerCreateNative = ffi.Pointer<ScannerWrapper> Function(
  ffi.Pointer<ffi.Pointer<ffi.Utf8>> hosts,
  ffi.Int32 hosts_count,
  ffi.Int32 start_port,
  ffi.Int32 end_port,
  ffi.Int32 timeout_ms,
  ffi.Int32 max_threads,
);

typedef ScannerCreateDart = ffi.Pointer<ScannerWrapper> Function(
  ffi.Pointer<ffi.Pointer<ffi.Utf8>>,
  int,
  int,
  int,
  int,
  int,
);

// scanner_destroy
typedef ScannerDestroyNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
);

typedef ScannerDestroyDart = void Function(
  ffi.Pointer<ScannerWrapper>,
);

// scanner_scan
typedef ScannerScanNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
);

typedef ScannerScanDart = void Function(
  ffi.Pointer<ScannerWrapper>,
);

// scanner_get_result_count
typedef ScannerGetResultCountNative = ffi.Int32 Function(
  ffi.Pointer<ScannerWrapper>,
);

typedef ScannerGetResultCountDart = int Function(
  ffi.Pointer<ScannerWrapper>,
);

// scanner_get_host_count
typedef ScannerGetHostCountNative = ffi.Int32 Function(
  ffi.Pointer<ScannerWrapper>,
);

typedef ScannerGetHostCountDart = int Function(
  ffi.Pointer<ScannerWrapper>,
);

// scanner_get_result
typedef ScannerGetResultNative = PortResult Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerGetResultDart = PortResult Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_get_host_status
typedef ScannerGetHostStatusNative = ffi.Int32 Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerGetHostStatusDart = int Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_set_scan_type
typedef ScannerSetScanTypeNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerSetScanTypeDart = void Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_set_enable_version_detection
typedef ScannerSetVersionDetectionNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerSetVersionDetectionDart = void Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_set_enable_banner_grabbing
typedef ScannerSetBannerGrabbingNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerSetBannerGrabbingDart = void Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_set_rate_limit
typedef ScannerSetRateLimitNative = Void Function(
  ffi.Pointer<ScannerWrapper>,
  ffi.Int32,
);

typedef ScannerSetRateLimitDart = void Function(
  ffi.Pointer<ScannerWrapper>,
  int,
);

// scanner_export_json
typedef ScannerExportJsonNative = ffi.Pointer<ffi.Char> Function(
  ffi.Pointer<ScannerWrapper>,
);

typedef ScannerExportJsonDart = ffi.Pointer<ffi.Char> Function(
  ffi.Pointer<ScannerWrapper>,
);

// scanner_free_json
typedef ScannerFreeJsonNative = Void Function(
  ffi.Pointer<ffi.Char>,
);

typedef ScannerFreeJsonDart = void Function(
  ffi.Pointer<ffi.Char>,
);

// ==================== Main Binding Class ====================

class PortScannerLib {
  late ScannerCreateDart _create;
  late ScannerDestroyDart _destroy;
  late ScannerScanDart _scan;
  late ScannerGetResultCountDart _getResultCount;
  late ScannerGetHostCountDart _getHostCount;
  late ScannerGetResultDart _getResult;
  late ScannerGetHostStatusDart _getHostStatus;
  late ScannerSetScanTypeDart _setScanType;
  late ScannerSetVersionDetectionDart _setVersionDetection;
  late ScannerSetBannerGrabbingDart _setBannerGrabbing;
  late ScannerSetRateLimitDart _setRateLimit;
  late ScannerExportJsonDart _exportJson;
  late ScannerFreeJsonDart _freeJson;

  late DynamicLibrary _lib;

  /// Load the native library
  /// 
  /// For macOS/iOS: libport_scanner.dylib
  /// For Linux/Android: libport_scanner.so
  /// For Windows: port_scanner.dll
  Future<void> load({String? path}) async {
    if (path != null) {
      _lib = DynamicLibrary.open(path);
    } else if (Platform.isMacOS || Platform.isIOS) {
      _lib = DynamicLibrary.open('libport_scanner.dylib');
    } else if (Platform.isAndroid || Platform.isLinux) {
      _lib = DynamicLibrary.open('libport_scanner.so');
    } else if (Platform.isWindows) {
      _lib = DynamicLibrary.open('port_scanner.dll');
    } else {
      throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
    }

    _setupFunctions();
  }

  void _setupFunctions() {
    _create = _lib
        .lookup<ScannerCreateNative>('scanner_create')
        .asFunction();
    _destroy = _lib
        .lookup<ScannerDestroyNative>('scanner_destroy')
        .asFunction();
    _scan = _lib
        .lookup<ScannerScanNative>('scanner_scan')
        .asFunction();
    _getResultCount = _lib
        .lookup<ScannerGetResultCountNative>('scanner_get_result_count')
        .asFunction();
    _getHostCount = _lib
        .lookup<ScannerGetHostCountNative>('scanner_get_host_count')
        .asFunction();
    _getResult = _lib
        .lookup<ScannerGetResultNative>('scanner_get_result')
        .asFunction();
    _getHostStatus = _lib
        .lookup<ScannerGetHostStatusNative>('scanner_get_host_status')
        .asFunction();
    _setScanType = _lib
        .lookup<ScannerSetScanTypeNative>('scanner_set_scan_type')
        .asFunction();
    _setVersionDetection = _lib
        .lookup<ScannerSetVersionDetectionNative>('scanner_set_enable_version_detection')
        .asFunction();
    _setBannerGrabbing = _lib
        .lookup<ScannerSetBannerGrabbingNative>('scanner_set_enable_banner_grabbing')
        .asFunction();
    _setRateLimit = _lib
        .lookup<ScannerSetRateLimitNative>('scanner_set_rate_limit')
        .asFunction();
    _exportJson = _lib
        .lookup<ScannerExportJsonNative>('scanner_export_json')
        .asFunction();
    _freeJson = _lib
        .lookup<ScannerFreeJsonNative>('scanner_free_json')
        .asFunction();
  }

  // ==================== Public API ====================

  /// Create a new scanner
  ffi.Pointer<ScannerWrapper> create({
    required List<String> hosts,
    int startPort = 1,
    int endPort = 1024,
    int timeoutMs = 1000,
    int maxThreads = 10,
  }) {
    final hostArray = hosts.map((h) => h.toNativeUtf8()).toList();
    final hostPtr = allocate<ffi.Pointer<ffi.Utf8>>(count: hosts.length);
    
    for (int i = 0; i < hosts.length; i++) {
      hostPtr[i] = hostArray[i];
    }

    final scanner = _create(
      hostPtr,
      hosts.length,
      startPort,
      endPort,
      timeoutMs,
      maxThreads,
    );

    // Free temporary allocations
    for (final h in hostArray) {
      h.dispose();
    }
    dealloc(hostPtr);

    return scanner;
  }

  /// Destroy scanner
  void destroy(ffi.Pointer<ScannerWrapper> scanner) {
    _destroy(scanner);
  }

  /// Run scan
  void scan(ffi.Pointer<ScannerWrapper> scanner) {
    _scan(scanner);
  }

  /// Get result count
  int getResultCount(ffi.Pointer<ScannerWrapper> scanner) {
    return _getResultCount(scanner);
  }

  /// Get host count
  int getHostCount(ffi.Pointer<ScannerWrapper> scanner) {
    return _getHostCount(scanner);
  }

  /// Get result at index
  PortResult getResult(ffi.Pointer<ScannerWrapper> scanner, int index) {
    return _getResult(scanner, index);
  }

  /// Get host status at index (0=ONLINE, 1=NO_PORTS, 2=OFFLINE)
  int getHostStatus(ffi.Pointer<ScannerWrapper> scanner, int index) {
    return _getHostStatus(scanner, index);
  }

  /// Set scan type
  void setScanType(ffi.Pointer<ScannerWrapper> scanner, int type) {
    _setScanType(scanner, type);
  }

  /// Enable version detection
  void setVersionDetection(ffi.Pointer<ScannerWrapper> scanner, bool enable) {
    _setVersionDetection(scanner, enable ? 1 : 0);
  }

  /// Enable banner grabbing
  void setBannerGrabbing(ffi.Pointer<ScannerWrapper> scanner, bool enable) {
    _setBannerGrabbing(scanner, enable ? 1 : 0);
  }

  /// Set rate limit (packets per second, 0 = unlimited)
  void setRateLimit(ffi.Pointer<ScannerWrapper> scanner, int packetsPerSec) {
    _setRateLimit(scanner, packetsPerSec);
  }

  /// Export results to JSON string
  String exportJson(ffi.Pointer<ScannerWrapper> scanner) {
    final jsonPtr = _exportJson(scanner);
    final jsonString = jsonPtr.toDartString();
    _freeJson(jsonPtr);
    return jsonString;
  }
}

/// Helper class for easier result parsing
class ScanResult {
  final String host;
  final int port;
  final bool isOpen;
  final bool isUdp;
  final String service;
  final String? version;
  final String? banner;
  final bool isSsl;

  ScanResult({
    required this.host,
    required this.port,
    required this.isOpen,
    this.isUdp = false,
    this.service = 'unknown',
    this.version,
    this.banner,
    this.isSsl = false,
  });

  @override
  String toString() {
    if (isOpen) {
      return 'Port $port $service${version != null ? ' ($version)' : ''}${isSsl ? ' [SSL]' : ''}';
    }
    return 'Port $port closed';
  }
}

/// Parse raw PortResult FFI struct into Dart object
ScanResult parsePortResult(PortResult result, PortScannerLib lib) {
  return ScanResult(
    host: result.host.toDartString(),
    port: result.port,
    isOpen: result.is_open == 1,
    isUdp: result.is_udp == 1,
    service: result.service.toDartString(),
    version: result.version.value != 0 ? result.version.toDartString() : null,
    banner: result.banner.value != 0 ? result.banner.toDartString() : null,
    isSsl: result.ssl == 1,
  );
}

/// Host status to string
String hostStatusToString(int status) {
  switch (status) {
    case 0: return 'ONLINE';
    case 1: return 'NO_PORTS';
    case 2: return 'OFFLINE';
    default: return 'UNKNOWN';
  }
}
