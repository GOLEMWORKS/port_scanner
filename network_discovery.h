#ifndef NETWORK_DISCOVERY_H
#define NETWORK_DISCOVERY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Network Discovery Module — discovers live hosts in a local network.
 * 
 * Finds live hosts in a CIDR range, extracts IP addresses and hostnames.
 * Zero external dependencies — only POSIX/Berkeley sockets.
 * 
 * Platform support:
 * - Linux (x86_64, arm64)
 * - macOS (x86_64, arm64)
 * - Android (arm64-v8a, armeabi-v7a)
 * - iOS (arm64)
 */

/* ==================== Enumerations ==================== */

/** Type of discovery method */
typedef enum {
    DISCOVERY_TYPE_PING = 0,          // ICMP Ping (basic liveness)
    DISCOVERY_TYPE_PING_BROADCAST = 1, // ARP + ICMP + UDP ping
    DISCOVERY_TYPE_ARP = 2            // ARP scan (fast, local network only)
} DiscoveryType;

/* ==================== Structures ==================== */

/**
 * Result of discovering a single host.
 * 
 * IMPORTANT for FFI: String fields (ip_address, hostname) are malloc'd
 * and must be freed using discovery_free_result().
 */
typedef struct {
    char* ip_address;    // IP address (malloc'd)
    char* hostname;      // Hostname (malloc'd, may be NULL if reverse-DNS failed)
    int is_online;       // 1 = online, 0 = offline
} DiscoveryResult;

/**
 * Discovery report with statistics.
 * 
 * IMPORTANT for FFI: results array and its string fields are malloc'd
 * and must be freed using discovery_free_report().
 */
typedef struct {
    int total_scanned;          // Total number of IP addresses scanned
    int online_count;           // Number of online hosts found
    int hostname_resolved;      // Number of hostnames resolved
    DiscoveryResult* results;   // Array of results (malloc'd)
} DiscoveryReport;

/* ==================== Opaque Handle ==================== */

/**
 * Opaque discovery wrapper handle.
 * Actual type is defined internally in network_discovery.cpp.
 */
typedef struct DiscoveryWrapper DiscoveryWrapper;

/* ==================== Core Functions ==================== */

/**
 * Create a new discovery scanner for a CIDR network.
 * 
 * @param network_cidr CIDR notation network (e.g., "192.168.1.0/24")
 * @param timeout_ms Timeout per host in milliseconds (default: 500)
 * @param max_threads Maximum number of discovery threads (default: 50)
 * @return DiscoveryWrapper* (must be freed with discovery_destroy)
 */
DiscoveryWrapper* discovery_create(const char* network_cidr,
                                    int timeout_ms,
                                    int max_threads);

/**
 * Destroy the discovery scanner and free all associated memory.
 * Note: This does NOT free DiscoveryReport — use discovery_free_report() first.
 */
void discovery_destroy(DiscoveryWrapper* wrapper);

/**
 * Run the discovery scan.
 * Call after configuring discovery with discovery_set_* functions.
 * Blocks until scan completes.
 */
void discovery_scan(DiscoveryWrapper* wrapper);

/* ==================== Configuration ==================== */

/**
 * Set discovery type (call BEFORE discovery_scan).
 */
void discovery_set_type(DiscoveryWrapper* wrapper, DiscoveryType type);

/**
 * Enable/disable reverse DNS resolution (call BEFORE discovery_scan).
 * Default: enabled.
 */
void discovery_set_enable_dns(DiscoveryWrapper* wrapper, int enable);

/* ==================== Result Retrieval ==================== */

/**
 * Get the total number of scanned hosts.
 */
int discovery_get_total_scanned(DiscoveryWrapper* wrapper);

/**
 * Get the number of online hosts found.
 */
int discovery_get_online_count(DiscoveryWrapper* wrapper);

/**
 * Get the number of resolved hostnames.
 */
int discovery_get_hostname_resolved(DiscoveryWrapper* wrapper);

/**
 * Get discovery result at specified index.
 * @return DiscoveryResult (by value; strings are pointers)
 */
DiscoveryResult discovery_get_result(DiscoveryWrapper* wrapper, int index);

/**
 * Get IP address string at specified index.
 * @return IP string (internal pointer, does NOT need free)
 */
const char* discovery_get_ip(DiscoveryWrapper* wrapper, int index);

/**
 * Get hostname string at specified index.
 * @return Hostname string (internal pointer, does NOT need free)
 */
const char* discovery_get_hostname(DiscoveryWrapper* wrapper, int index);

/* ==================== Report ==================== */

/**
 * Get full discovery report.
 * @return DiscoveryReport* (must be freed with discovery_free_report)
 */
DiscoveryReport* discovery_get_report(DiscoveryWrapper* wrapper);

/* ==================== Memory Management ==================== */

/**
 * Free a single DiscoveryResult (frees malloc'd string fields).
 */
void discovery_free_result(DiscoveryResult* result);

/**
 * Free a DiscoveryReport returned by discovery_get_report()
 * (frees results array and all string fields).
 */
void discovery_free_report(DiscoveryReport* report);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_DISCOVERY_H
