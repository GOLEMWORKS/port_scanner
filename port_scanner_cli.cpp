#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include "port_scanner.h"

void printUsage(const char* program) {
    std::cout << "Port Scanner v2.0 (MVP) - Penetration testing port scanner (C API)\n" << std::endl;
    std::cout << "Usage: " << program << " [options]\n" << std::endl;
    std::cout << "Host options:" << std::endl;
    std::cout << "  -h, --host <hostname>        Host to scan (default: localhost). Can be specified multiple times" << std::endl;
    std::cout << "  -f, --file <filename>        File with list of hosts (one per line)" << std::endl;
    std::cout << std::endl;
    std::cout << "Port options:" << std::endl;
    std::cout << "  -s, --start <port>           Start port (default: 1)" << std::endl;
    std::cout << "  -e, --end <port>             End port (default: 1024)" << std::endl;
    std::cout << "  -r, --range <start-end>      Port range (alternative to -s and -e)" << std::endl;
    std::cout << std::endl;
    std::cout << "Scan options:" << std::endl;
    std::cout << "  --syn                        SYN scan (stealth, requires root/CAP_NET_RAW)" << std::endl;
    std::cout << "  --udp                        UDP scan" << std::endl;
    std::cout << "  -t, --timeout <ms>           Timeout in milliseconds (default: 1000)" << std::endl;
    std::cout << "  -T, --threads <count>        Number of threads (default: 10)" << std::endl;
    std::cout << "      --rate-limit <n>         Rate limit in packets/sec (default: unlimited)" << std::endl;
    std::cout << std::endl;
    std::cout << "Features:" << std::endl;
    std::cout << "      --version-detect         Enable version detection" << std::endl;
    std::cout << "      --banner-grab            Enable banner grabbing" << std::endl;
    std::cout << "      --exploit <name>         Check for vulnerabilities (heartbleed, shellshock, ghostscript, polecache)" << std::endl;
    std::cout << "      --json <file>            Export results to JSON file" << std::endl;
    std::cout << std::endl;
    std::cout << "Presets:" << std::endl;
    std::cout << "      --quick                  Quick scan: top-100 ports, connect scan" << std::endl;
    std::cout << "      --stealth                SYN scan, top-1024 ports" << std::endl;
    std::cout << "      --vuln                   Scan + vulnerability checks" << std::endl;
    std::cout << "      --full                   Full scan: all ports, all checks" << std::endl;
    std::cout << "      --all-scans              Enable all features (SYN + version + banner)" << std::endl;
    std::cout << std::endl;
    std::cout << "Other:" << std::endl;
    std::cout << "  -v, --version                Show version" << std::endl;
    std::cout << "  -?, --help                   Show this help" << std::endl;
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

static ExploitCheck parseExploitName(const std::string& name) {
    if (name == "heartbleed") return EXPLOIT_HEARTBLEED;
    if (name == "shellshock") return EXPLOIT_SHELLSHOCK;
    if (name == "ghostscript") return EXPLOIT_GHOSTSCRIPT;
    if (name == "polecache") return EXPLOIT_POLECACHE;
    return EXPLOIT_NONE;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> hosts;
    int startPort = 1;
    int endPort = 1024;
    int timeoutMs = 1000;
    int maxThreads = 10;
    int rateLimit = 0; // 0 = unlimited
    
    // Feature flags
    bool useSYN = false;
    bool enableUDP = false;
    bool enableVersionDetect = false;
    bool enableBannerGrab = false;
    ExploitCheck exploitCheck = EXPLOIT_NONE;
    std::string exploitName;
    std::string jsonFile;
    
    // Preset flags
    bool presetQuick = false;
    bool presetStealth = false;
    bool presetVuln = false;
    bool presetFull = false;

    // Parse arguments
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
        } else if (strcmp(argv[i], "--syn") == 0) {
            useSYN = true;
        } else if (strcmp(argv[i], "--udp") == 0) {
            enableUDP = true;
        } else if (strcmp(argv[i], "--version-detect") == 0) {
            enableVersionDetect = true;
        } else if (strcmp(argv[i], "--banner-grab") == 0) {
            enableBannerGrab = true;
        } else if (strcmp(argv[i], "--exploit") == 0) {
            exploitName = argv[++i];
            exploitCheck = parseExploitName(exploitName);
            if (exploitCheck == EXPLOIT_NONE) {
                std::cerr << "Error: Unknown exploit '" << exploitName << "'. "
                          << "Available: heartbleed, shellshock, ghostscript, polecache" << std::endl;
                return 1;
            }
        } else if (strcmp(argv[i], "--rate-limit") == 0) {
            rateLimit = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--json") == 0) {
            jsonFile = argv[++i];
        } else if (strcmp(argv[i], "--all-scans") == 0) {
            useSYN = true;
            enableVersionDetect = true;
            enableBannerGrab = true;
        } else if (strcmp(argv[i], "--quick") == 0) {
            presetQuick = true;
            startPort = 1;
            endPort = 100;
        } else if (strcmp(argv[i], "--stealth") == 0) {
            presetStealth = true;
            useSYN = true;
            startPort = 1;
            endPort = 1024;
        } else if (strcmp(argv[i], "--vuln") == 0) {
            presetVuln = true;
            enableVersionDetect = true;
            // Exploit check will be set by user or default to none
        } else if (strcmp(argv[i], "--full") == 0) {
            presetFull = true;
            useSYN = true;
            enableUDP = true;
            enableVersionDetect = true;
            enableBannerGrab = true;
            startPort = 1;
            endPort = 65535;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version-only") == 0) {
            std::cout << "Port Scanner v2.0 (MVP)" << std::endl;
            return 0;
        } else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }

    // Apply presets if no explicit values were set
    if (presetQuick) {
        std::cout << "[INFO] Using preset: quick scan (top-100 ports, connect scan)" << std::endl;
    }
    if (presetStealth) {
        std::cout << "[INFO] Using preset: stealth scan (SYN scan, top-1024 ports)" << std::endl;
    }
    if (presetVuln) {
        std::cout << "[INFO] Using preset: vulnerability scan (version detection enabled)" << std::endl;
    }
    if (presetFull) {
        std::cout << "[INFO] Using preset: full scan (all ports, all checks)" << std::endl;
    }

    if (hosts.empty()) {
        hosts.push_back("localhost");
    }

    const char** hostArray = new const char*[hosts.size()];
    for (size_t i = 0; i < hosts.size(); i++) {
        hostArray[i] = hosts[i].c_str();
    }

    // Determine scan type
    ScanType scanType = SCAN_TYPE_CONNECT;
    if (useSYN && enableUDP) {
        // Priority: if both SYN and UDP requested, we'll use SYN for TCP and add UDP ports
        scanType = SCAN_TYPE_SYN;
        std::cout << "[INFO] Mixed scan: SYN for TCP + UDP scan" << std::endl;
    } else if (useSYN) {
        scanType = SCAN_TYPE_SYN;
    } else if (enableUDP) {
        scanType = SCAN_TYPE_UDP;
        
        // Warn about slow UDP scan for large port ranges
        int portCount = endPort - startPort + 1;
        if (portCount > 1024) {
            std::cout << "[WARN] UDP scan is significantly slower than TCP scan. "
                      << "Consider limiting port range (max recommended: 1024 ports)." << std::endl;
        }
        if (portCount > 65535) {
            std::cerr << "[ERROR] UDP scan of all 65535 ports is not recommended. "
                      << "Use --range to limit the port range." << std::endl;
            delete[] hostArray;
            return 1;
        }
    }

    ScannerWrapper* scanner = scanner_create(hostArray, static_cast<int>(hosts.size()),
                                              startPort, endPort, timeoutMs, maxThreads);
    
    if (!scanner) {
        std::cerr << "Error: Failed to create scanner" << std::endl;
        delete[] hostArray;
        return 1;
    }

    // Apply settings
    scanner_set_scan_type(scanner, scanType);
    scanner_set_enable_version_detection(scanner, enableVersionDetect ? 1 : 0);
    scanner_set_enable_banner_grabbing(scanner, enableBannerGrab ? 1 : 0);
    scanner_set_exploit_check(scanner, exploitCheck);
    if (rateLimit > 0) {
        scanner_set_rate_limit(scanner, rateLimit);
    }

    std::cout << "\n[INFO] Starting scan..." << std::endl;
    std::cout << "[INFO] Hosts: " << hosts.size() << ", Ports: " << startPort << "-" << endPort;
    if (useSYN) std::cout << ", Type: SYN";
    if (enableUDP) std::cout << ", Type: UDP";
    if (enableVersionDetect) std::cout << ", Version detection: enabled";
    if (enableBannerGrab) std::cout << ", Banner grabbing: enabled";
    if (exploitCheck != EXPLOIT_NONE) std::cout << ", Exploit check: " << exploitName;
    std::cout << std::endl;
    std::cout << std::endl;

    scanner_scan(scanner);

    delete[] hostArray;

    int resultCount = scanner_get_result_count(scanner);
    int openCount = 0;
    
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Total results: " << resultCount << std::endl;

    for (int i = 0; i < resultCount; i++) {
        PortResult result = scanner_get_result(scanner, i);
        if (result.is_open) {
            openCount++;
            std::cout << "[" << result.host << "] Port " << result.port 
                      << " OPEN (" << result.service << ")";
            if (result.version) {
                std::cout << " v" << result.version;
            }
            if (result.banner) {
                std::cout << " | Banner: " << result.banner;
            }
            if (result.ssl) {
                std::cout << " [SSL]";
            }
            std::cout << std::endl;
        }
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Open ports: " << openCount << " / " << resultCount << std::endl;

    std::cout << "\n=== Host Status ===" << std::endl;
    for (size_t i = 0; i < hosts.size(); i++) {
        HostStatus status = scanner_get_host_status(scanner, static_cast<int>(i));
        const char* statusStr = (status == HOST_STATUS_ONLINE) ? "ONLINE" :
                                (status == HOST_STATUS_NO_PORTS) ? "NO-PORTS" : "OFFLINE";
        std::cout << hosts[i] << ": " << statusStr << std::endl;
    }

    // Export to JSON if requested
    if (!jsonFile.empty()) {
        char* json = scanner_export_json(scanner);
        std::ofstream outFile(jsonFile);
        if (outFile.is_open()) {
            outFile << json;
            outFile.close();
            std::cout << "\n[INFO] Results exported to: " << jsonFile << std::endl;
        } else {
            std::cerr << "Error: Cannot write to file " << jsonFile << std::endl;
        }
        scanner_free_json(json);
    }

    scanner_destroy(scanner);

    return 0;
}
