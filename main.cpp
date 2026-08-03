#include <iostream>
#include <cstring>
#include "port_scanner.h"

void printResults(ScannerWrapper* scanner) {
    int resultCount = scanner_get_result_count(scanner);
    int hostCount = scanner_get_host_count(scanner);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCAN RESULTS" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    for (int h = 0; h < hostCount; h++) {
        HostStatus status = scanner_get_host_status(scanner, h);
        std::cout << "Host #" << (h + 1) << " status: ";
        switch (status) {
            case HOST_STATUS_ONLINE:   std::cout << "ONLINE"; break;
            case HOST_STATUS_NO_PORTS: std::cout << "NO-PORTS"; break;
            default:                   std::cout << "OFFLINE"; break;
        }
        std::cout << std::endl;
    }
    
    std::cout << "\nOpen ports:\n";
    std::cout << "----------------------------------------" << std::endl;
    
    for (int i = 0; i < resultCount; i++) {
        PortResult result = scanner_get_result(scanner, i);
        if (result.is_open) {
            std::cout << "  [" << (result.ssl ? "SSL" : "TCP") << "] "
                      << result.host << ":" << result.port
                      << " - " << (result.service ? result.service : "unknown");
            if (result.version) {
                std::cout << " (" << result.version << ")";
            }
            std::cout << std::endl;
            if (result.banner && strlen(result.banner) > 0) {
                std::cout << "    Banner: " << result.banner << std::endl;
            }
        }
    }
    
    // Export JSON
    char* json = scanner_export_json(scanner);
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "JSON Report:\n" << json << std::endl;
    scanner_free_json(json);
    
    // Free all results
    for (int i = 0; i < resultCount; i++) {
        PortResult result = scanner_get_result(scanner, i);
        scanner_free_result(&result);
    }
}

int main(int argc, char* argv[]) {
    std::cout << "Port Scanner - Demo" << std::endl;
    std::cout << "===================\n" << std::endl;
    
    // Default targets if no arguments
    const char* defaultHosts[] = {"127.0.0.1"};
    int hostsCount = 1;
    int startPort = 1;
    int endPort = 1024;
    int timeoutMs = 500;
    int maxThreads = 10;
    
    // Parse command line arguments (optional)
    if (argc >= 2) {
        hostsCount = 1;
        // Simple: first arg is host
    }
    if (argc >= 4) {
        startPort = atoi(argv[2]);
        endPort = atoi(argv[3]);
    }
    if (argc >= 5) {
        timeoutMs = atoi(argv[4]);
    }
    
    // Create scanner
    ScannerWrapper* scanner = scanner_create(
        defaultHosts, hostsCount,
        startPort, endPort,
        timeoutMs, maxThreads
    );
    
    if (!scanner) {
        std::cerr << "Failed to create scanner!" << std::endl;
        return 1;
    }
    
    // Configure scan options
    scanner_set_scan_type(scanner, SCAN_TYPE_CONNECT);  // Use connect scan (no root needed)
    scanner_set_enable_version_detection(scanner, 0);   // Disable version detection
    scanner_set_enable_banner_grabbing(scanner, 0);     // Disable banner grabbing
    
    // Run scan
    std::cout << "Scanning " << defaultHosts[0] 
              << " ports " << startPort << "-" << endPort 
              << " (timeout: " << timeoutMs << "ms)" << std::endl;
    std::cout << std::endl;
    
    scanner_scan(scanner);
    
    // Print results
    printResults(scanner);
    
    // Cleanup
    scanner_destroy(scanner);
    
    std::cout << "\nDone." << std::endl;
    return 0;
}
