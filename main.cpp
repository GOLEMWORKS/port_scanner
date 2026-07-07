#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <atomic>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

class PortScanner {
private:
    std::vector<std::string> hosts;
    enum class HostStatus { ONLINE, NO_PORTS, OFFLINE };
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

    struct PortResult {
        std::string host;
        int port;
        bool isOpen;
        std::string service;
    };

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

    bool checkHostAlive(const std::string& host) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);

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
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
        
        close(sock);
        return result == 0;
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
                results.push_back({task.first, task.second, isOpen, getServiceName(task.second)});
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
                hostStatus[hostIndex] = HostStatus::OFFLINE;
                offlineHostsCount++;
                return;
            }
        }
        
        if (hasOpenPort) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [ONLINE]" << std::endl << std::flush;
            hostStatus[hostIndex] = HostStatus::ONLINE;
        } else if (gotResponse) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [NO-PORTS]" << std::endl << std::flush;
            hostStatus[hostIndex] = HostStatus::NO_PORTS;
            noPortsHostsCount++;
        } else {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [OFFLINE]" << std::endl << std::flush;
            hostStatus[hostIndex] = HostStatus::OFFLINE;
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
                int timeoutMs = 1000, int maxThreads = 10)
        : hosts(hosts), startPort(startPort), endPort(endPort),
          timeoutMs(timeoutMs), maxThreads(maxThreads) {
        hostStatus.resize(hosts.size(), HostStatus::OFFLINE);
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
            if (hostStatus[i] == HostStatus::ONLINE || hostStatus[i] == HostStatus::NO_PORTS) {
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
        hostStatus.push_back(HostStatus::OFFLINE);
    }
};

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

    PortScanner scanner(hosts, startPort, endPort, timeoutMs, maxThreads);
    scanner.scan();

    return 0;
}
