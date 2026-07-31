#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <atomic>
#include <cstring>
#include <random>
#include <map>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "port_scanner.h"

#pragma pack(push, 1)

// ICMP types for error handling
static const uint8_t ICMP_DEST_UNREACHABLE = 3;
static const uint8_t ICMP_PORT_UNREACHABLE = 3;

struct TCPPacket {
    struct {
        uint16_t src_port;        // Will be set in host byte order, converted before send
        uint16_t dst_port;        // Will be set in host byte order, converted before send
        uint32_t seq_num;         // Will be set in network byte order
        uint32_t ack_num;         // Will be set in network byte order
        uint8_t data_offset: 4;   // 4-bit TCP header length (in 32-bit words)
        uint8_t flags: 6;         // 6-bit TCP flags
        uint8_t reserved: 2;      // 2-bit reserved
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
    } tcp_header;
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t reserved: 8;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;
};
#pragma pack(pop)

static uint16_t tcpChecksum(uint16_t* addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t w;
    
    while (nleft > 1) {
        memcpy(&w, addr, 2);
        sum += w;
        addr++;
        nleft -= 2;
    }
    
    if (nleft == 1) {
        uint16_t u = 0;
        memcpy(&u, addr, 1);
        sum += u;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

enum InternalHostStatus {
    INTERNAL_HOST_STATUS_ONLINE = 0,
    INTERNAL_HOST_STATUS_NO_PORTS = 1,
    INTERNAL_HOST_STATUS_OFFLINE = 2
};

struct InternalPortResult {
    std::string host;
    int port;
    bool isOpen;
    std::string service;
    std::string version;
    std::string banner;
};

class PortScanner {
private:
    std::vector<std::string> hosts;
    std::vector<InternalHostStatus> hostStatus;
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

    std::vector<InternalPortResult> results;
    std::mutex resultsMutex;
    int totalTasks;
    
    bool useSYNScan;
    bool enableVersionDetection;
    bool enableBannerGrabbing;

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
        if (useSYNScan) {
            return isPortOpenSYN(host, port);
        }
        return isPortOpenConnect(host, port);
    }

    bool isPortOpenConnect(const std::string& host, int port) {
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

    bool isPortOpenSYN(const std::string& host, int port) {
        // Resolve hostname to IP
        struct in_addr resolved_ip{};
        if (inet_pton(AF_INET, host.c_str(), &resolved_ip) <= 0) {
            addrinfo hints{}, *result;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
                return false;
            }
            resolved_ip = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }

        // Try to create raw socket for SYN scan
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            // Graceful degradation: fallback to connect scan if no root privileges
            // SYN scan requires CAP_NET_RAW (Linux) or root/admin (macOS)
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[WARN] Raw sockets unavailable (need root/CAP_NET_RAW). "
                      << "Falling back to connect scan for " << host << std::endl << std::flush;
            useSYNScan = false; // Disable SYN scan for subsequent calls
            return isPortOpenConnect(host, port);
        }

        // Set receive timeout
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Prepare socket address
        sockaddr_in dst_addr{};
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_port = htons(port);
        dst_addr.sin_addr = resolved_ip;

        // Random source port
        static std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<uint32_t> seq_dist(1, UINT32_MAX);
        uint16_t src_port = std::uniform_int_distribution<uint16_t>(1024, 65535)(rng);
        uint32_t seq_num = seq_dist(rng);

        // Build TCP SYN packet (20 bytes header, no options)
        TCPPacket packet{};
        packet.tcp_header.src_port = htons(src_port);
        packet.tcp_header.dst_port = htons(port);
        packet.tcp_header.seq_num = htonl(seq_num);
        packet.tcp_header.ack_num = 0;
        packet.tcp_header.data_offset = 5; // 5 * 4 = 20 bytes
        packet.tcp_header.reserved = 0;
        packet.tcp_header.flags = TH_SYN;
        packet.tcp_header.window = 1024;
        packet.tcp_header.checksum = 0;
        packet.tcp_header.urgent_ptr = 0;

        // Build pseudo header for checksum calculation (RFC 793)
        packet.pseudo_header.src_addr = resolved_ip.s_addr;
        packet.pseudo_header.dst_addr = resolved_ip.s_addr;
        packet.pseudo_header.reserved = 0;
        packet.pseudo_header.protocol = IPPROTO_TCP;
        packet.pseudo_header.tcp_length = htons(20); // TCP header only (no data)

        // Calculate checksum over pseudo-header + TCP header
        uint16_t checksum = tcpChecksum((uint16_t*)&packet, 40); // 20 (TCP) + 20 (pseudo) = 40
        packet.tcp_header.checksum = checksum;

        // Send SYN packet
        ssize_t sent = sendto(sock, &packet, sizeof(packet.tcp_header), 0,
                              (sockaddr*)&dst_addr, sizeof(dst_addr));
        
        if (sent < 0) {
            close(sock);
            return false;
        }

        // Wait for response with improved error handling
        char response[128]{};
        ssize_t received = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
        
        if (received < 0) {
            int err = errno;
            close(sock);
            // ECONNREFUSED means destination refused connection (port closed)
            // This shouldn't happen with raw sockets, but handle it gracefully
            if (err == ECONNREFUSED) {
                return false; // Port is closed
            }
            // ETIMEDOUT or other errors - port might be filtered or closed
            return false;
        }

        // Analyze response
        bool isOpen = false;
        
        if (received >= 40) {
            auto* resp = (TCPPacket*)response;
            uint8_t flags = resp->tcp_header.flags;
            
            // Check if it's a response to our SYN packet
            // Response dst_port should match our src_port, and src_port should match target port
            if (resp->tcp_header.dst_port == htons(src_port) &&
                resp->tcp_header.src_port == htons(port)) {
                
                if (flags & TH_RST) {
                    // RST (with or without ACK) - port is closed
                    isOpen = false;
                    // Send RST+ACK to clean up (stealth abort)
                    resp->tcp_header.flags = TH_RST | TH_ACK;
                    resp->tcp_header.ack_num = htonl(ntohl(resp->tcp_header.seq_num) + 1);
                    resp->tcp_header.checksum = 0;
                    resp->tcp_header.reserved = 0;
                    uint16_t rst_checksum = tcpChecksum((uint16_t*)resp, 40);
                    resp->tcp_header.checksum = rst_checksum;
                    sendto(sock, resp, sizeof(resp->tcp_header), 0, 
                           (sockaddr*)&dst_addr, sizeof(dst_addr));
                } else if (flags & TH_ACK) {
                    // SYN-ACK received - port is OPEN and listening!
                    isOpen = true;
                    // Send RST+ACK to abort connection (stealth - don't complete 3-way handshake)
                    resp->tcp_header.flags = TH_RST | TH_ACK;
                    resp->tcp_header.ack_num = htonl(ntohl(resp->tcp_header.seq_num) + 1);
                    resp->tcp_header.checksum = 0;
                    resp->tcp_header.reserved = 0;
                    uint16_t rst_checksum = tcpChecksum((uint16_t*)resp, 40);
                    resp->tcp_header.checksum = rst_checksum;
                    sendto(sock, resp, sizeof(resp->tcp_header), 0,
                           (sockaddr*)&dst_addr, sizeof(dst_addr));
                }
                // If neither RST nor ACK, ignore (malformed or unexpected response)
            }
        } else if (received >= 20) {
            // Could be ICMP error message (e.g., "Destination Unreachable")
            // ICMP type 3, code 3 = Destination Unreachable, Port Unreachable
            uint8_t icmp_type = (uint8_t)response[0];
            uint8_t icmp_code = (uint8_t)response[1];
            if (icmp_type == ICMP_DEST_UNREACHABLE && icmp_code == ICMP_PORT_UNREACHABLE) {
                isOpen = false; // Port is closed
            }
        }

        close(sock);
        return isOpen;
    }

    bool isPortOpenUDP(const std::string& host, int port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        struct in_addr resolved_ip;
        if (inet_pton(AF_INET, host.c_str(), &resolved_ip) <= 0) {
            addrinfo hints{}, *result;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
                return false;
            }
            resolved_ip = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            return false;
        }

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Send a minimal UDP packet (could be service-specific probe)
        const char probe[] = "";
        ssize_t sent = sendto(sock, probe, 0, 0,
                              (sockaddr*)&addr, sizeof(addr));
        
        if (sent < 0 && errno != ENOTCONN) {
            close(sock);
            return false;
        }

        // Try to receive ICMP port unreachable (closed) or any response (open)
        char response[64]{};
        ssize_t received = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
        
        close(sock);

        // If we get ICMP port unreachable, port is closed
        // If we get any response or timeout, port might be open
        if (received > 0) {
            // Check if it's ICMP port unreachable (type 3, code 3)
            if (received >= 20) {
                uint8_t icmp_type = ((uint8_t*)response)[0];
                uint8_t icmp_code = ((uint8_t*)response)[1];
                if (icmp_type == 3 && icmp_code == 3) {
                    return false; // Port closed
                }
            }
            return true; // Got some response - likely open or filtered
        }

        // Timeout - port might be open (filtered by firewall)
        // For UDP, timeout usually means open/filtered
        return false; // Conservative: assume closed on timeout
    }

    std::map<std::string, std::string> versionCache;

    std::string detectVersion(const std::string& host, int port) {
        // Check cache first
        std::string cacheKey = host + ":" + std::to_string(port);
        auto cacheIt = versionCache.find(cacheKey);
        if (cacheIt != versionCache.end()) {
            return cacheIt->second;
        }

        // Connect to port
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        struct in_addr resolved_ip;
        if (inet_pton(AF_INET, host.c_str(), &resolved_ip) <= 0) {
            addrinfo hints{}, *result;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
                return "";
            }
            resolved_ip = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return "";
        }

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return "";
        }

        std::string version = "";
        char buffer[1024]{};

        // Send protocol-specific probe and read response
        switch (port) {
            case 21: { // FTP - FEAT command (RFC 2389)
                send(sock, "FEAT\r\n", 6, 0);
                usleep(500000); // Wait 500ms
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Extract version from banner like "220 (vsFTPd 3.0.3)"
                    if (strstr(buffer, "vsFTPd")) {
                        version = "vsFTPd";
                    } else if (strstr(buffer, "ProFTPD")) {
                        version = "ProFTPD";
                    } else if (strstr(buffer, "FTP")) {
                        version = "FTP";
                    }
                }
                break;
            }
            case 22: { // SSH
                send(sock, "SSH-2.0-PortScanner\r\n", 21, 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Parse SSH banner like "SSH-2.0-OpenSSH_8.9p1"
                    std::string resp(buffer);
                    size_t dash = resp.find('-');
                    if (dash != std::string::npos) {
                        version = resp.substr(dash + 1, resp.find('\n') - dash - 1);
                        if (version.empty()) version = resp.substr(dash + 1);
                    }
                }
                break;
            }
            case 25: { // SMTP
                send(sock, "EHLO scanner\r\n", 14, 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    if (strstr(buffer, "Postfix")) {
                        version = "Postfix";
                    } else if (strstr(buffer, "Exim")) {
                        version = "Exim";
                    } else if (strstr(buffer, "Microsoft")) {
                        version = "Microsoft ESMTP";
                    }
                }
                break;
            }
            case 80: { // HTTP
                const char* request = "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n";
                send(sock, request, strlen(request), 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Extract Server header
                    std::string resp(buffer);
                    size_t serverPos = resp.find("Server: ");
                    if (serverPos != std::string::npos) {
                        size_t start = serverPos + 8;
                        size_t end = resp.find('\r', start);
                        if (end != std::string::npos) {
                            version = resp.substr(start, end - start);
                        } else {
                            version = resp.substr(start);
                        }
                    }
                }
                break;
            }
            case 11211: { // Memcached
                send(sock, "version\r\n", 9, 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Response like "VERSION 1.6.17\r\n"
                    std::string resp(buffer);
                    size_t versionPos = resp.find("VERSION ");
                    if (versionPos != std::string::npos) {
                        version = resp.substr(versionPos + 8, resp.find('\r', versionPos) - versionPos - 8);
                    }
                }
                break;
            }
            default: {
                // Try to read any automatic banner
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Extract first line as potential banner/version
                    std::string resp(buffer);
                    size_t newline = resp.find('\n');
                    if (newline != std::string::npos) {
                        version = resp.substr(0, newline);
                        // Remove trailing \r if present
                        if (!version.empty() && version.back() == '\r') {
                            version.pop_back();
                        }
                    }
                }
                break;
            }
        }

        close(sock);

        // Cache the result
        versionCache[cacheKey] = version;
        return version;
    }

    std::string grabBanner(const std::string& host, int port) {
        // Connect to port
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        struct in_addr resolved_ip;
        if (inet_pton(AF_INET, host.c_str(), &resolved_ip) <= 0) {
            addrinfo hints{}, *result;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
                return "";
            }
            resolved_ip = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return "";
        }

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return "";
        }

        // Wait for automatic banner
        char buffer[1024]{};
        usleep(500000); // Wait 500ms for banner
        
        ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        close(sock);

        if (received > 0) {
            buffer[received] = '\0';
            std::string resp(buffer);
            
            // Extract first line (most common banner format)
            size_t newline = resp.find('\n');
            if (newline != std::string::npos) {
                return resp.substr(0, newline);
            }
            
            // Return entire response if no newline
            return resp;
        }

        return "";
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
                InternalPortResult pr;
                pr.host = task.first;
                pr.port = task.second;
                pr.isOpen = isOpen;
                pr.service = getServiceName(task.second);
                
                // Run version detection if enabled
                if (isOpen && enableVersionDetection) {
                    pr.version = detectVersion(task.first, task.second);
                }
                
                // Run banner grabbing if enabled
                if (isOpen && enableBannerGrabbing) {
                    pr.banner = grabBanner(task.first, task.second);
                }
                
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
                hostStatus[hostIndex] = INTERNAL_HOST_STATUS_OFFLINE;
                offlineHostsCount++;
                return;
            }
        }
        
        if (hasOpenPort) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [ONLINE]" << std::endl << std::flush;
            hostStatus[hostIndex] = INTERNAL_HOST_STATUS_ONLINE;
        } else if (gotResponse) {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [NO-PORTS]" << std::endl << std::flush;
            hostStatus[hostIndex] = INTERNAL_HOST_STATUS_NO_PORTS;
            noPortsHostsCount++;
        } else {
            std::lock_guard<std::mutex> lock(outputMutex);
            std::cout << "[" << host << "] [OFFLINE]" << std::endl << std::flush;
                hostStatus[hostIndex] = INTERNAL_HOST_STATUS_OFFLINE;
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
          timeoutMs(timeoutMs), maxThreads(maxThreads),
          useSYNScan(false), enableVersionDetection(false), enableBannerGrabbing(false) {
        hostStatus.resize(hosts.size(), INTERNAL_HOST_STATUS_OFFLINE);
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
            if (hostStatus[i] == INTERNAL_HOST_STATUS_ONLINE || hostStatus[i] == INTERNAL_HOST_STATUS_NO_PORTS) {
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

    const std::vector<InternalPortResult>& getResults() const {
        return results;
    }

    const std::vector<InternalHostStatus>& getHostStatus() const {
        return hostStatus;
    }

    void addHost(const std::string& host) {
        hosts.push_back(host);
        hostStatus.push_back(INTERNAL_HOST_STATUS_OFFLINE);
    }

    void setSYNScan(bool enable) {
        useSYNScan = enable;
    }

    bool getSYNScan() const {
        return useSYNScan;
    }

    void setEnableVersionDetection(bool enable) {
        enableVersionDetection = enable;
    }

    void setEnableBannerGrabbing(bool enable) {
        enableBannerGrabbing = enable;
    }

    bool getVersionDetectionEnabled() const {
        return enableVersionDetection;
    }

    bool getBannerGrabbingEnabled() const {
        return enableBannerGrabbing;
    }

    std::string getScanTypeString() const {
        return useSYNScan ? "syn" : "connect";
    }

    int getStartPort() const { return startPort; }
    int getEndPort() const { return endPort; }
    size_t getHostCount() const { return hosts.size(); }
};

struct CPortResult {
    char* host;
    int port;
    int is_open;
    int is_udp;
    char* service;
    char* version;
    char* banner;
    int ssl;
};

struct ScannerWrapper {
    PortScanner* scanner;
    std::vector<std::string> hosts;
    std::vector<CPortResult> portResults;
    std::vector<InternalHostStatus> hostStatusValues;
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
    
    const std::vector<InternalPortResult>& results = scanner->scanner->getResults();
    const std::vector<InternalHostStatus>& statuses = scanner->scanner->getHostStatus();
    
    scanner->portResults.clear();
    for (const auto& r : results) {
        CPortResult pr{};
        pr.host = strdup(r.host.c_str());
        pr.port = r.port;
        pr.is_open = r.isOpen ? 1 : 0;
        pr.is_udp = 0;
        pr.service = strdup(r.service.c_str());
        pr.version = nullptr;
        pr.banner = nullptr;
        pr.ssl = 0;
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
    PortResult empty{};
    if (!scanner || index < 0 || index >= static_cast<int>(scanner->portResults.size())) {
        return empty;
    }
    const CPortResult& cr = scanner->portResults[index];
    empty.host = cr.host;
    empty.port = cr.port;
    empty.is_open = cr.is_open;
    empty.is_udp = cr.is_udp;
    empty.service = cr.service;
    empty.version = cr.version;
    empty.banner = cr.banner;
    empty.ssl = cr.ssl;
    return empty;
}

HostStatus scanner_get_host_status(ScannerWrapper* scanner, int index) {
    if (!scanner || index < 0 || index >= static_cast<int>(scanner->hostStatusValues.size())) {
        return HOST_STATUS_OFFLINE;
    }
    InternalHostStatus status = scanner->hostStatusValues[index];
    switch (status) {
        case INTERNAL_HOST_STATUS_ONLINE: return HOST_STATUS_ONLINE;
        case INTERNAL_HOST_STATUS_NO_PORTS: return HOST_STATUS_NO_PORTS;
        case INTERNAL_HOST_STATUS_OFFLINE: return HOST_STATUS_OFFLINE;
        default: return HOST_STATUS_OFFLINE;
    }
}

void scanner_free_result(CPortResult* result) {
    if (!result) return;
    if (result->host) free(result->host);
    if (result->service) free(result->service);
    if (result->version) free(result->version);
    if (result->banner) free(result->banner);
}

void scanner_free_results(CPortResult* results, int count) {
    if (!results || count <= 0) return;
    for (int i = 0; i < count; i++) {
        scanner_free_result(&results[i]);
    }
    free(results);
}

void scanner_set_scan_type(ScannerWrapper* wrapper, ScanType type) {
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setSYNScan(type == SCAN_TYPE_SYN);
}

void scanner_set_exploit_check(ScannerWrapper* wrapper, ExploitCheck check) {
    // TODO: Implement exploit checks
    (void)wrapper;
    (void)check;
}

void scanner_set_enable_version_detection(ScannerWrapper* wrapper, int enable) {
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setEnableVersionDetection(enable != 0);
}

void scanner_set_enable_banner_grabbing(ScannerWrapper* wrapper, int enable) {
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setEnableBannerGrabbing(enable != 0);
}

void scanner_set_rate_limit(ScannerWrapper* wrapper, int packets_per_sec) {
    // TODO: Implement rate limiting
    (void)wrapper;
    (void)packets_per_sec;
}

char* scanner_export_json(ScannerWrapper* wrapper) {
    if (!wrapper || !wrapper->scanner) {
        return strdup("{}");
    }

    const auto& results = wrapper->portResults;
    const auto& statuses = wrapper->hostStatusValues;
    
    auto jsonEscape = [](const std::string& s) -> std::string {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    };

    // Get current time
    char timeBuf[64];
    time_t now = time(nullptr);
    struct tm* tm_info = gmtime(&now);
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    std::string json = "{\n";
    json += "  \"scan_info\": {\n";
    json += "    \"scan_type\": \"" + wrapper->scanner->getScanTypeString() + "\",\n";
    json += "    \"port_range\": \"" + std::to_string(wrapper->scanner->getStartPort()) + "-" + std::to_string(wrapper->scanner->getEndPort()) + "\",\n";
    json += "    \"timestamp\": \"" + std::string(timeBuf) + "\",\n";
    json += "    \"options\": {\n";
    json += "      \"version_detection\": " + std::string(wrapper->scanner->getVersionDetectionEnabled() ? "true" : "false") + ",\n";
    json += "      \"banner_grabbing\": " + std::string(wrapper->scanner->getBannerGrabbingEnabled() ? "true" : "false") + ",\n";
    json += "      \"exploit_checks\": false\n";
    json += "    }\n";
    json += "  },\n";
    json += "  \"hosts\": [\n";

    int onlineHosts = 0;
    int totalOpenPorts = 0;
    
    for (size_t h = 0; h < statuses.size(); h++) {
        HostStatus status = scanner_get_host_status(wrapper, static_cast<int>(h));
        std::string statusStr;
        switch (status) {
            case HOST_STATUS_ONLINE: statusStr = "online"; onlineHosts++; break;
            case HOST_STATUS_NO_PORTS: statusStr = "no-ports"; break;
            default: statusStr = "offline"; break;
        }

        json += "    {\n";
        json += "      \"address\": \"" + jsonEscape(wrapper->hosts[h]) + "\",\n";
        json += "      \"status\": \"" + statusStr + "\",\n";
        json += "      \"ports\": [\n";

        bool firstPort = true;
        int hostOpenPorts = 0;
        
        for (const auto& pr : results) {
            // Check if this result belongs to current host
            std::string hostStr(pr.host);
            if (hostStr == wrapper->hosts[h]) {
                if (!firstPort) json += ",\n";
                firstPort = false;
                
                bool isOpen = pr.is_open != 0;
                std::string service = pr.service ? pr.service : "unknown";
                std::string version = pr.version ? pr.version : "";
                std::string banner = pr.banner ? pr.banner : "";
                bool ssl = pr.ssl != 0;
                
                json += "        {\n";
                json += "          \"port\": " + std::to_string(pr.port) + ",\n";
                json += "          \"protocol\": \"tcp\",\n";
                json += "          \"state\": " + std::string(isOpen ? "\"open\"" : "\"closed\"") + ",\n";
                json += "          \"service\": \"" + jsonEscape(service) + "\"";
                
                if (!version.empty()) {
                    json += ",\n          \"version\": \"" + jsonEscape(version) + "\"";
                }
                if (!banner.empty()) {
                    json += ",\n          \"banner\": \"" + jsonEscape(banner) + "\"";
                }
                json += ",\n          \"ssl\": " + std::string(ssl ? "true" : "false");
                json += ",\n          \"vulnerabilities\": [\n            {\n";
                json += "              \"name\": \"none\",\n";
                json += "              \"severity\": 0,\n";
                json += "              \"cve\": null,\n";
                json += "              \"description\": null\n";
                json += "            }\n";
                json += "          ]\n";
                json += "        }";
                
                if (isOpen) {
                    totalOpenPorts++;
                    hostOpenPorts++;
                }
            }
        }

        json += "\n      ]\n";
        json += "    }";
        if (h < statuses.size() - 1) json += ",";
        json += "\n";
    }

    json += "  ],\n";
    json += "  \"summary\": {\n";
    json += "    \"total_hosts\": " + std::to_string(statuses.size()) + ",\n";
    json += "    \"online_hosts\": " + std::to_string(onlineHosts) + ",\n";
    json += "    \"total_open_ports\": " + std::to_string(totalOpenPorts) + ",\n";
    json += "    \"vulnerable_ports\": 0\n";
    json += "  }\n";
    json += "}";

    return strdup(json.c_str());
}

ScanReport* scanner_get_report(ScannerWrapper* wrapper) {
    // TODO: Implement report generation
    (void)wrapper;
    return nullptr;
}

void scanner_free_report(ScanReport* report) {
    // TODO: Implement report cleanup
    (void)report;
}

void scanner_free_json(char* json) {
    if (json) free(json);
}

}
