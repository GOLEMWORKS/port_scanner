#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include "port_scanner.h"

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --host <hostname>    Host to scan (default: localhost)" << std::endl;
    std::cout << "  -f, --file <filename>    File with list of hosts" << std::endl;
    std::cout << "  -s, --start <port>       Start port (default: 1)" << std::endl;
    std::cout << "  -e, --end <port>         End port (default: 1024)" << std::endl;
    std::cout << "  -t, --timeout <ms>       Timeout in milliseconds (default: 1000)" << std::endl;
    std::cout << "  -T, --threads <count>    Number of threads (default: 10)" << std::endl;
    std::cout << "  -r, --range <start-end>  Port range (alternative to -s and -e)" << std::endl;
    std::cout << "  -v, --version            Show version" << std::endl;
    std::cout << "  -?, --help               Show this help" << std::endl;
}

std::vector<std::string> loadHostsFromFile(const std::string& filename) {
    std::vector<std::string> hosts;
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty() && line[0] != '#') {
            hosts.push_back(line);
        }
    }
    
    return hosts;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> hosts;
    int startPort = 1;
    int endPort = 1024;
    int timeoutMs = 1000;
    int maxThreads = 10;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) {
            hosts.push_back(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            std::string filename = argv[++i];
            std::ifstream testFile(filename);
            if (!testFile.is_open()) {
                std::cerr << "Error: Cannot open file " << filename << std::endl;
                return 1;
            }
            std::vector<std::string> fileHosts = loadHostsFromFile(filename);
            if (fileHosts.empty()) {
                std::cerr << "Error: No valid hosts found in " << filename << std::endl;
                return 1;
            }
            hosts.insert(hosts.end(), fileHosts.begin(), fileHosts.end());
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--start") == 0) {
            startPort = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--end") == 0) {
            endPort = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
            timeoutMs = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--threads") == 0) {
            maxThreads = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--range") == 0) {
            std::string range = argv[++i];
            size_t dash = range.find('-');
            if (dash != std::string::npos) {
                startPort = std::stoi(range.substr(0, dash));
                endPort = std::stoi(range.substr(dash + 1));
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            std::cout << "Port Scanner v1.2" << std::endl;
            return 0;
        } else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (hosts.empty()) {
        hosts.push_back("localhost");
    }

    const char** hostArray = new const char*[hosts.size()];
    for (size_t i = 0; i < hosts.size(); i++) {
        hostArray[i] = hosts[i].c_str();
    }

    ScannerWrapper* scanner = scanner_create(hostArray, static_cast<int>(hosts.size()),
                                              startPort, endPort, timeoutMs, maxThreads);
    
    if (!scanner) {
        std::cerr << "Failed to create scanner" << std::endl;
        delete[] hostArray;
        return 1;
    }

    scanner_scan(scanner);

    delete[] hostArray;

    int resultCount = scanner_get_result_count(scanner);
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Total results: " << resultCount << std::endl;

    for (int i = 0; i < resultCount; i++) {
        PortResult result = scanner_get_result(scanner, i);
        std::cout << "[" << result.host << "] Port " << result.port 
                  << " - " << (result.is_open ? "OPEN" : "CLOSED")
                  << " (" << result.service << ")" << std::endl;
    }

    std::cout << "\n=== Host Status ===" << std::endl;
    for (size_t i = 0; i < hosts.size(); i++) {
        HostStatus status = scanner_get_host_status(scanner, static_cast<int>(i));
        const char* statusStr = (status == HOST_STATUS_ONLINE) ? "ONLINE" :
                                (status == HOST_STATUS_NO_PORTS) ? "NO-PORTS" : "OFFLINE";
        std::cout << hosts[i] << ": " << statusStr << std::endl;
    }

    scanner_destroy(scanner);

    return 0;
}
