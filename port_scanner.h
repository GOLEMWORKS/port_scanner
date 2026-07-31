#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Port Scanner C API
 * 
 * Stable ABI for Dart FFI and other foreign language bindings.
 * All memory allocated by the library must be freed using scanner_free_* functions.
 * 
 * Platform support:
 * - Linux (x86_64, arm64)
 * - macOS (x86_64, arm64)
 * - Android (arm64-v8a, armeabi-v7a)
 * - iOS (arm64)
 */

/* ==================== Enumerations ==================== */

typedef enum {
    HOST_STATUS_ONLINE = 0,         // Host is online, open ports found
    HOST_STATUS_NO_PORTS = 1,       // Host is online, but no open ports
    HOST_STATUS_OFFLINE = 2         // Host is offline or unreachable
} HostStatus;

typedef enum {
    SCAN_TYPE_SYN = 0,              // SYN stealth scan (requires root)
    SCAN_TYPE_CONNECT = 1,          // Standard TCP connect scan
    SCAN_TYPE_UDP = 2               // UDP scan
} ScanType;

typedef enum {
    EXPLOIT_NONE = 0,
    EXPLOIT_HEARTBLEED = 1,         // CVE-2014-0160 (OpenSSL)
    EXPLOIT_SHELLSHOCK = 2,         // CVE-2014-6271 (Bash)
    EXPLOIT_GHOSTSCRIPT = 3,        // Ghostscript RCE
    EXPLOIT_POLECACHE = 4           // Memcached unauthorized access
} ExploitCheck;

/* ==================== Structures ==================== */

/**
 * Result of scanning a single port.
 * 
 * IMPORTANT for FFI: String fields (host, service, version, banner) are malloc'd
 * and must be freed using scanner_free_result() or manually with free().
 */
typedef struct {
    char* host;      // Hostname or IP (malloc'd, may be NULL)
    int port;        // Port number
    int is_open;     // 1 if open, 0 if closed
    int is_udp;      // 1 if UDP port, 0 if TCP
    char* service;   // Service name (e.g., "SSH", "HTTP") (malloc'd, may be NULL)
    char* version;   // Service version (malloc'd, may be NULL)
    char* banner;    // Service banner (malloc'd, may be NULL)
    int ssl;         // 1 if SSL/TLS detected, 0 otherwise
} PortResult;

/**
 * Result of an exploit check.
 */
typedef struct {
    int result;              // 1 if vulnerability found, 0 if not, -1 if error
    char* exploit_name;      // Name of vulnerability (malloc'd, may be NULL)
    char* description;       // Description (malloc'd, may be NULL)
    char* cve;              // CVE number (malloc'd, may be NULL)
    char* affected_version; // Affected version (malloc'd, may be NULL)
    int severity;           // 1=info, 2=low, 3=medium, 4=high, 5=critical
} ExploitResult;

/**
 * Full scan report with statistics.
 */
typedef struct {
    int host_count;                    // Total number of hosts scanned
    int port_count;                    // Total number of ports scanned
    int open_count;                    // Number of open ports
    int vulnerable_count;              // Number of vulnerable ports
    HostStatus* host_statuses;         // Array of host statuses (malloc'd)
    PortResult* results;               // Array of port results (malloc'd)
    ExploitResult* exploit_results;    // Array of exploit results (malloc'd)
} ScanReport;

/* ==================== Opaque Handle ==================== */

/**
 * Opaque scanner handle.
 * Actual type is defined internally in port_scanner.cpp.
 */
typedef struct ScannerWrapper ScannerWrapper;

/* ==================== Core Functions ==================== */

/**
 * Create a new scanner instance.
 * 
 * @param hosts Array of hostnames/IPs (not freed by library)
 * @param hosts_count Number of hosts
 * @param start_port First port to scan
 * @param end_port Last port to scan (inclusive)
 * @param timeout_ms Connection timeout in milliseconds
 * @param max_threads Maximum number of scanning threads
 * @return ScannerWrapper* (must be freed with scanner_destroy)
 */
ScannerWrapper* scanner_create(const char* hosts[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads);

/**
 * Destroy the scanner and free all associated memory.
 * Note: This does NOT free PortResult strings - use scanner_free_result() first.
 */
void scanner_destroy(ScannerWrapper* scanner);

/**
 * Run the scan operation.
 * Call after configuring scanner with scanner_set_* functions.
 */
void scanner_scan(ScannerWrapper* scanner);

/* ==================== Configuration ==================== */

/**
 * Set scan type (call BEFORE scanner_scan).
 */
void scanner_set_scan_type(ScannerWrapper* scanner, ScanType type);

/**
 * Set exploit check to perform (call BEFORE scanner_scan).
 */
void scanner_set_exploit_check(ScannerWrapper* scanner, ExploitCheck check);

/**
 * Enable/disable version detection (call BEFORE scanner_scan).
 */
void scanner_set_enable_version_detection(ScannerWrapper* scanner, int enable);

/**
 * Enable/disable banner grabbing (call BEFORE scanner_scan).
 */
void scanner_set_enable_banner_grabbing(ScannerWrapper* scanner, int enable);

/**
 * Set rate limit in packets per second (0 = unlimited).
 * Useful for evading IDS/IPS systems.
 */
void scanner_set_rate_limit(ScannerWrapper* scanner, int packets_per_sec);

/* ==================== Result Retrieval ==================== */

/**
 * Get the number of port results.
 */
int scanner_get_result_count(ScannerWrapper* scanner);

/**
 * Get host count (number of hosts scanned).
 */
int scanner_get_host_count(ScannerWrapper* scanner);

/**
 * Get result at specified index.
 * @return PortResult (returns empty result if index out of bounds)
 */
PortResult scanner_get_result(ScannerWrapper* scanner, int index);

/**
 * Get host status at specified index.
 */
HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index);

/* ==================== Export ==================== */

/**
 * Export scan results to JSON string.
 * @return JSON string (must be freed with scanner_free_json)
 */
char* scanner_export_json(ScannerWrapper* scanner);

/**
 * Get full scan report (includes exploit results).
 * @return ScanReport* (must be freed with scanner_free_report)
 */
ScanReport* scanner_get_report(ScannerWrapper* scanner);

/* ==================== Memory Management ==================== */

/**
 * Free a single PortResult (frees malloc'd string fields).
 */
void scanner_free_result(PortResult* result);

/**
 * Free multiple PortResults.
 */
void scanner_free_results(PortResult* results, int count);

/**
 * Free JSON string returned by scanner_export_json().
 */
void scanner_free_json(char* json);

/**
 * Free ScanReport returned by scanner_get_report().
 */
void scanner_free_report(ScanReport* report);

#ifdef __cplusplus
}
#endif

#endif // PORT_SCANNER_H
