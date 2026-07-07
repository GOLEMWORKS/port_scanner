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

typedef struct {
    char* host;
    int port;
    int is_open;
    char* service;
} PortResult;

typedef struct ScannerWrapper ScannerWrapper;

ScannerWrapper* scanner_create(const char* hosts[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads);

void scanner_destroy(ScannerWrapper* scanner);

void scanner_scan(ScannerWrapper* scanner);

int scanner_get_result_count(ScannerWrapper* scanner);

PortResult scanner_get_result(ScannerWrapper* scanner, int index);

HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index);

#ifdef __cplusplus
}
#endif

#endif
