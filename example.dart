/// Example usage of Port Scanner Dart FFI
/// 
/// Run with: dart example.dart

import 'dart:io';
import 'package:port_scanner/port_scanner_ffi.dart';

void main(List<String> args) async {
  print('=== Port Scanner Dart FFI Example ===\n');

  // Load the library
  final scannerLib = PortScannerLib();
  await scannerLib.load();
  print('✓ Library loaded\n');

  // Example 1: Quick scan of localhost
  print('--- Example 1: Quick scan of localhost (ports 1-100) ---');
  await scanHosts(
    scannerLib,
    hosts: ['localhost'],
    startPort: 1,
    endPort: 100,
  );
  print();

  // Example 2: Scan with version detection
  print('--- Example 2: Scan with version detection ---');
  await scanWithOptions(
    scannerLib,
    hosts: ['localhost'],
    startPort: 1,
    endPort: 1024,
    enableVersionDetection: true,
    enableBannerGrabbing: true,
  );
  print();

  // Example 3: JSON export
  print('--- Example 3: JSON export ---');
  await exportToJson(scannerLib);
  print();

  // Example 4: SYN scan (requires root/admin)
  print('--- Example 4: SYN scan (requires root) ---');
  await synScanExample(scannerLib);
}

/// Basic scan example
Future<void> scanHosts(
  PortScannerLib lib, {
  required List<String> hosts,
  int startPort = 1,
  int endPort = 100,
}) async {
  final scanner = lib.create(
    hosts: hosts,
    startPort: startPort,
    endPort: endPort,
    timeoutMs: 1000,
    maxThreads: 10,
  );

  try {
    print('Scanning ${hosts.join(', ')}...');
    lib.scan(scanner);

    final count = lib.getResultCount(scanner);
    int openCount = 0;

    for (int i = 0; i < count; i++) {
      final result = lib.getResult(scanner, i);
      final scanResult = parsePortResult(result, lib);
      if (scanResult.isOpen) {
        openCount++;
        print('  ${scanResult.toString()}');
      }
    }

    print('\nFound $openCount open port(s)\n');
  } finally {
    lib.destroy(scanner);
  }
}

/// Scan with advanced options
Future<void> scanWithOptions(
  PortScannerLib lib, {
  required List<String> hosts,
  int startPort = 1,
  int endPort = 1024,
  bool enableVersionDetection = false,
  bool enableBannerGrabbing = false,
  int rateLimit = 0,
}) async {
  final scanner = lib.create(
    hosts: hosts,
    startPort: startPort,
    endPort: endPort,
    timeoutMs: 1000,
    maxThreads: 10,
  );

  try {
    // Configure scanner
    if (enableVersionDetection) {
      lib.setVersionDetection(scanner, true);
    }
    if (enableBannerGrabbing) {
      lib.setBannerGrabbing(scanner, true);
    }
    if (rateLimit > 0) {
      lib.setRateLimit(scanner, rateLimit);
    }

    print('Scanning with options:');
    if (enableVersionDetection) print('  - Version detection: enabled');
    if (enableBannerGrabbing) print('  - Banner grabbing: enabled');
    if (rateLimit > 0) print('  - Rate limit: $rateLimit pkt/s');
    print();

    lib.scan(scanner);

    final count = lib.getResultCount(scanner);
    int openCount = 0;

    for (int i = 0; i < count; i++) {
      final result = lib.getResult(scanner, i);
      final scanResult = parsePortResult(result, lib);
      if (scanResult.isOpen) {
        openCount++;
        if (scanResult.version != null) {
          print('  ${scanResult.toString()}');
        }
      }
    }

    print('\nFound $openCount open port(s)\n');
  } finally {
    lib.destroy(scanner);
  }
}

/// JSON export example
Future<void> exportToJson(PortScannerLib lib) async {
  final scanner = lib.create(
    hosts: ['localhost'],
    startPort: 1,
    endPort: 100,
    timeoutMs: 1000,
    maxThreads: 10,
  );

  try {
    lib.scan(scanner);

    final json = lib.exportJson(scanner);
    print('JSON exported (${json.length} bytes):');
    
    // Print first 500 chars
    final preview = json.length > 500 ? json.substring(0, 500) + '...' : json;
    print(preview);
    print('');
  } finally {
    lib.destroy(scanner);
  }
}

/// SYN scan example (requires elevated privileges)
Future<void> synScanExample(PortScannerLib lib) async {
  if (!Platform.isLinux && !Platform.isMacOS) {
    print('SYN scan is only supported on Linux/macOS\n');
    return;
  }

  final scanner = lib.create(
    hosts: ['localhost'],
    startPort: 1,
    endPort: 1024,
    timeoutMs: 1000,
    maxThreads: 10,
  );

  try {
    // Set SYN scan type
    lib.setScanType(scanner, 0); // SCAN_TYPE_SYN

    print('Running SYN scan (stealth mode)...');
    lib.scan(scanner);

    final count = lib.getResultCount(scanner);
    int openCount = 0;

    for (int i = 0; i < count; i++) {
      final result = lib.getResult(scanner, i);
      final scanResult = parsePortResult(result, lib);
      if (scanResult.isOpen) {
        openCount++;
        print('  Port ${scanResult.port} OPEN (${scanResult.service})');
      }
    }

    print('\nFound $openCount open port(s)\n');
  } finally {
    lib.destroy(scanner);
  }
}

/// Helper to scan multiple hosts and aggregate results
Future<void> scanMultipleHosts(
  PortScannerLib lib,
  List<String> hosts,
) async {
  print('Scanning multiple hosts: ${hosts.join(', ')}');
  
  final scanner = lib.create(
    hosts: hosts,
    startPort: 1,
    endPort: 100,
    timeoutMs: 1000,
    maxThreads: 20,
  );

  try {
    lib.scan(scanner);

    final hostCount = lib.getHostCount(scanner);
    print('\nHost status:');
    
    for (int i = 0; i < hostCount; i++) {
      final status = lib.getHostStatus(scanner, i);
      print('  ${hosts[i]}: ${hostStatusToString(status)}');
    }
  } finally {
    lib.destroy(scanner);
  }
}
