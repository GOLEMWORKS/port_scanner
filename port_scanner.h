#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HOST_STATUS_ONLINE = 0,
    HOST_STATUS_NO_PORTS = 1,
    HOST_STATUS_OFFLINE = 2
} HostStatus;

typedef enum {
    SCAN_TYPE_SYN = 0,
    SCAN_TYPE_CONNECT = 1,
    SCAN_TYPE_UDP = 2
} ScanType;

typedef enum {
    EXPLOIT_NONE = 0,
    EXPLOIT_HEARTBLEED = 1,
    EXPLOIT_SHELLSHOCK = 2,
    EXPLOIT_GHOSTSCRIPT = 3,
    EXPLOIT_POLECACHE = 4
} ExploitCheck;

typedef struct {
    char* host;
    int port;
    int is_open;
    int is_udp;
    char* service;
    char* version;
    char* banner;
    int ssl;
} PortResult;

typedef struct {
    int result;
    char* exploit_name;
    char* description;
    char* cve;
    char* affected_version;
    int severity;
} ExploitResult;

typedef struct {
    int host_count;
    int port_count;
    int open_count;
    int vulnerable_count;
    HostStatus* host_statuses;
    PortResult* results;
    ExploitResult* exploit_results;
} ScanReport;

typedef struct ScannerWrapper ScannerWrapper;

ScannerWrapper* scanner_create(const char* hosts[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads);

void scanner_destroy(ScannerWrapper* scanner);

void scanner_scan(ScannerWrapper* scanner);

void scanner_set_scan_type(ScannerWrapper* scanner, ScanType type);
void scanner_set_exploit_check(ScannerWrapper* scanner, ExploitCheck check);
void scanner_set_enable_version_detection(ScannerWrapper* scanner, int enable);
void scanner_set_enable_banner_grabbing(ScannerWrapper* scanner, int enable);
void scanner_set_rate_limit(ScannerWrapper* scanner, int packets_per_sec);

char* scanner_export_json(ScannerWrapper* scanner);
ScanReport* scanner_get_report(ScannerWrapper* scanner);

void scanner_free_report(ScanReport* report);
void scanner_free_json(char* json);

int scanner_get_result_count(ScannerWrapper* scanner);

PortResult scanner_get_result(ScannerWrapper* scanner, int index);

HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index);

#ifdef __cplusplus
}
#endif

#endif
