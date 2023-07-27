#include <iostream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

std::string get_ip(const std::string& interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        return "";
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
        std::cerr << "Failed to get IP address for the interface: " << interface << std::endl;
        close(sock);
        return "";
    }

    close(sock);

    struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr_in->sin_addr), ip_address, INET_ADDRSTRLEN);

    return std::string(ip_address);
}