#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <atomic>
#include <cstring>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

enum HostStatus {
    HOST_STATUS_ONLINE = 0,
    HOST_STATUS_NO_PORTS = 1,
    HOST_STATUS_OFFLINE = 2
};

struct PortResult {
    std::string host;
    int port;
    bool isOpen;
    std::string service;
};

class PortScanner {
private:
    std::vector<std::string> hosts;
    std::vector<HostStatus> hostStatus;
    int startPort;
    int endPort;
    int timeoutMs;
    int maxThreads;
    std::vector<std::thread> threads;
    std::vector<std::pair<std::string, int>> workQueue;
    std::mutex queueMutex;
    std::atomic<int> completedTasks{0};
    std::atomic<int> openPortsCount{0};
    std::atomic<int> noPortsHostsCount{0};
    std::atomic<int> offlineHostsCount{0};
    std::mutex outputMutex;

    std::vector<PortResult> results;
    std::mutex resultsMutex;
    int totalTasks;

    static std::string getServiceName(int port) {
        switch (port) {
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 445: return "SMB";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 8080: return "HTTP-Proxy";
            default: return "unknown";
        }
    }

    bool isPortOpen(const std::string& host, int port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
            addrinfo hints{}, *result;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
                return false;
            }
            addr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
        
        close(sock);
        return result == 0;
    }

    void workerThread() {
        while (true) {
            std::pair<std::string, int> task;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (workQueue.empty()) {
                    if (completedTasks.load() >= totalTasks) {
                        break;
                    }
                    continue;
                }
                task = workQueue.back();
                workQueue.pop_back();
            }

            bool isOpen = isPortOpen(task.first, task.second);
            
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                PortResult pr;
                pr.host = task.first;
                pr.port = task.second;
                pr.isOpen = isOpen;
                pr.service = getServiceName(task.second);
    results.push_back(pr);
    }
            
            if (isOpen) {
                openPortsCount++;
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[" << task.first << "] [OPEN] Port " << task.second << " - " << getServiceName(task.second) << std::endl << std::flush;
                }
            }

            completedTasks++;
        }
    }

    void scanHost(const std::string& host, int hostIndex) {
        bool hasOpenPort = false;
        bool gotResponse = false;
        
        for (int port = startPort; port <= endPort; port++) {
            if (isPortOpen(host, port)) {
                hasOpenPort = true;
                gotResponse = true;
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            if (port >= startPort + 5) {
                gotResponse = true;
            }
            
            if (port % 10 == 0 && !gotResponse) {
                std::lock_guard<std::mutex> lock(outputMutex);
                std::cout << "[" << host << "] [OFFLINE]" << std::endl << std::flush;
                hostStatus[hostIndex] = HOST_STATUS_OFFLINE;
                offlineHostsCount++;
                return;
            }
        }
        
        if (hasOpenPort) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [ONLINE]" << std::endl << std::flush;
            hostStatus[hostIndex] = HOST_STATUS_ONLINE;
        } else if (gotResponse) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [NO-PORTS]" << std::endl << std::flush;
            hostStatus[hostIndex] = HOST_STATUS_NO_PORTS;
            noPortsHostsCount++;
        } else {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [OFFLINE]" << std::endl << std::flush;
            hostStatus[hostIndex] = HOST_STATUS_OFFLINE;
            offlineHostsCount++;
        }
    }

    void printProgress() {
        if (totalTasks == 0) return;
        int lastProgress = -1;
        while (true) {
            int progress = (completedTasks.load() * 100) / totalTasks;
            if (progress != lastProgress) {
                std::cout << "\rProgress: " << progress << "% (" 
                          << completedTasks.load() << "/" << totalTasks << ")\r"
                          << std::flush;
                lastProgress = progress;
            }
            if (completedTasks.load() >= totalTasks) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout << std::endl;
    }

public:
    PortScanner(const std::vector<std::string>& hosts, int startPort, int endPort, 
                int timeoutMs, int maxThreads)
        : hosts(hosts), startPort(startPort), endPort(endPort),
          timeoutMs(timeoutMs), maxThreads(maxThreads) {
        hostStatus.resize(hosts.size(), HOST_STATUS_OFFLINE);
    }

    void scan() {
        std::cout << "Starting scan of " << hosts.size() << " host(s):" << std::endl;
        for (const auto& h : hosts) {
            std::cout << "  - " << h << std::endl;
        }
        std::cout << "Port range: " << startPort << "-" << endPort << std::endl;
        std::cout << "Timeout: " << timeoutMs << "ms, Threads: " << maxThreads << std::endl;
        std::cout << "----------------------------------------" << std::endl;

        for (size_t i = 0; i < hosts.size(); i++) {
            scanHost(hosts[i], i);
        }

        for (size_t i = 0; i < hosts.size(); i++) {
            if (hostStatus[i] == HOST_STATUS_ONLINE || hostStatus[i] == HOST_STATUS_NO_PORTS) {
                for (int port = startPort; port <= endPort; port++) {
                    workQueue.push_back({hosts[i], port});
                }
            }
        }

        totalTasks = workQueue.size();
        completedTasks = 0;

        std::thread progressThread(&PortScanner::printProgress, this);

        for (int i = 0; i < maxThreads; i++) {
            threads.emplace_back(&PortScanner::workerThread, this);
        }

        for (auto& t : threads) {
            t.join();
        }

        progressThread.join();

        std::cout << "----------------------------------------" << std::endl;
        std::cout << "Scan complete. Found " << openPortsCount.load() 
                  << " open port(s). " << (hosts.size() - noPortsHostsCount.load() - offlineHostsCount.load())
                  << " ONLINE, " << noPortsHostsCount.load() << " NO-PORTS, "
                  << offlineHostsCount.load() << " OFFLINE host(s)." << std::endl;
    }

    const std::vector<PortResult>& getResults() const {
        return results;
    }

    const std::vector<HostStatus>& getHostStatus() const {
        return hostStatus;
    }

    void addHost(const std::string& host) {
        hosts.push_back(host);
        hostStatus.push_back(HOST_STATUS_OFFLINE);
    }
};

struct ScannerWrapper {
    PortScanner* scanner;
    std::vector<std::string> hosts;
    std::vector<PortResult> portResults;
    std::vector<HostStatus> hostStatusValues;
};

extern "C" {

ScannerWrapper* scanner_create(const char* hosts_arr[], int hosts_count,
                               int start_port, int end_port,
                               int timeout_ms, int max_threads) {
    if (!hosts_arr || hosts_count <= 0) {
        return nullptr;
    }

    ScannerWrapper* wrapper = new ScannerWrapper();
    
    for (int i = 0; i < hosts_count; i++) {
        if (hosts_arr[i]) {
            wrapper->hosts.push_back(std::string(hosts_arr[i]));
        }
    }

    wrapper->scanner = new PortScanner(wrapper->hosts, start_port, end_port, 
                                        timeout_ms, max_threads);
    return wrapper;
}

void scanner_destroy(ScannerWrapper* scanner) {
    if (scanner) {
        if (scanner->scanner) {
            delete scanner->scanner;
            scanner->scanner = nullptr;
        }
        delete scanner;
    }
}

void scanner_scan(ScannerWrapper* scanner) {
    if (!scanner || !scanner->scanner) return;
    
    scanner->scanner->scan();
    
    const std::vector<PortResult>& results = scanner->scanner->getResults();
    const std::vector<HostStatus>& statuses = scanner->scanner->getHostStatus();
    
    scanner->portResults.clear();
    for (const auto& r : results) {
        PortResult pr;
        pr.host = strdup(r.host.c_str());
        pr.port = r.port;
        pr.isOpen = r.isOpen ? 1 : 0;
        pr.service = strdup(r.service.c_str());
        scanner->portResults.push_back(pr);
    }
    
    scanner->hostStatusValues.clear();
    for (const auto& s : statuses) {
        scanner->hostStatusValues.push_back(s);
    }
}

int scanner_get_result_count(ScannerWrapper* scanner) {
    if (!scanner) return 0;
    return static_cast<int>(scanner->portResults.size());
}

PortResult scanner_get_result(ScannerWrapper* scanner, int index) {
    PortResult empty = {nullptr, 0, 0, nullptr};
    if (!scanner || index < 0 || index >= static_cast<int>(scanner->portResults.size())) {
        return empty;
    }
    return scanner->portResults[index];
}

HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index) {
    if (!scanner || index < 0 || index >= static_cast<int>(scanner->hostStatusValues.size())) {
        return HOST_STATUS_OFFLINE;
    }
    return scanner->hostStatusValues[index];
}

}
