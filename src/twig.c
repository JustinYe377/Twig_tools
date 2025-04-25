#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>

#define ETHER_HDR_LEN 14
#define MAX_PACKET_SIZE 2000

// PCAP global header
struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};
// PCAP per-packet header
struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

// Compute one's-complement checksum over raw data, return in network byte order
static uint16_t checksum(const void *data, size_t length) {
    const uint16_t *ptr = data;
    uint32_t sum = 0;
    while (length > 1) {
        sum += ntohs(*ptr++);
        length -= 2;
    }
    if (length == 1) {
        sum += (*(const uint8_t*)ptr) << 8;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    return htons((uint16_t)~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "Usage: %s -i A.B.C.D_P\n", argv[0]);
        return 1;
    }
    char addr_str[INET_ADDRSTRLEN]; int prefix;
    if (sscanf(argv[2], "%15[^_]_%d", addr_str, &prefix) != 2) {
        fprintf(stderr, "Invalid interface spec: %s\n", argv[2]);
        return 1;
    }
    struct in_addr addr;
    if (!inet_pton(AF_INET, addr_str, &addr)) {
        fprintf(stderr, "Invalid IP: %s\n", addr_str);
        return 1;
    }
    uint32_t host = ntohl(addr.s_addr);
    uint32_t mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    uint32_t net = host & mask;
    struct in_addr net_addr = { htonl(net) };
    char net_base[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &net_addr, net_base, sizeof(net_base));
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "%s_%d.dmp", net_base, prefix);
    fprintf(stderr, "[twig] Using pcap file: %s\n", fname);

    int fd_in = open(fname, O_RDONLY);
    int fd_out = open(fname, O_RDWR | O_APPEND);
    if (fd_in < 0 || fd_out < 0) { perror("open"); return 1; }

    // skip global pcap header
    struct pcap_file_header gh;
    if (read(fd_in, &gh, sizeof(gh)) != sizeof(gh)) { fprintf(stderr, "read GH failed\n"); return 1; }
    int swap_endian = (gh.magic == 0xd4c3b2a1);

    struct pcap_pkthdr ph;
    uint8_t buf[MAX_PACKET_SIZE];

    while (1) {
        // read packet header
        ssize_t r = read(fd_in, &ph, sizeof(ph));
        if (r == 0) { usleep(10000); continue; }
        if (r != sizeof(ph)) break;

        uint32_t caplen = swap_endian ? ntohl(ph.caplen) : ph.caplen;
        if (caplen > MAX_PACKET_SIZE) { lseek(fd_in, caplen, SEEK_CUR); continue; }
        if (read(fd_in, buf, caplen) != caplen) break;

        // Ethernet: ethertype at offset 12-13
        uint16_t ethertype = ntohs(*(uint16_t*)(buf + 12));
        if (ethertype != 0x0800) continue; // not IPv4

        // IP header begins at offset 14
        uint8_t *ip = buf + ETHER_HDR_LEN;
        int ihl = (ip[0] & 0x0F) * 4;
        uint8_t protocol = ip[9];
        uint32_t src_ip = *(uint32_t*)(ip + 12);
        uint32_t dst_ip = *(uint32_t*)(ip + 16);

        // ICMP echo request
        if (protocol == 1 && caplen >= ETHER_HDR_LEN + ihl + 8) {
            uint8_t *icmp = ip + ihl;
            if (icmp[0] == 8) {
                // swap MACs
                for (int i = 0; i < 6; i++) { uint8_t t = buf[i]; buf[i] = buf[6+i]; buf[6+i] = t; }
                // swap IPs
                *(uint32_t*)(ip+12) = dst_ip;
                *(uint32_t*)(ip+16) = src_ip;
                // ICMP reply type
                icmp[0] = 0;
                // zero checksum then recalc
                *(uint16_t*)(icmp+2) = 0;
                size_t icmplen = caplen - ETHER_HDR_LEN - ihl;
                *(uint16_t*)(icmp+2) = checksum(icmp, icmplen);
                // recalc IP checksum
                *(uint16_t*)(ip+10) = 0;
                *(uint16_t*)(ip+10) = checksum(ip, ihl);
                // append new packet
                struct iovec iov[2] = { {&ph, sizeof(ph)}, {buf, caplen} };
                writev(fd_out, iov, 2);
                fprintf(stderr, "[twig] Replied to ICMP echo request\n");
            }
            continue;
        }

        // UDP
        if (protocol == 17 && caplen >= ETHER_HDR_LEN + ihl + 8) {
            uint8_t *udp = ip + ihl;
            uint16_t src_port = ntohs(*(uint16_t*)(udp));
            uint16_t dst_port = ntohs(*(uint16_t*)(udp + 2));
            uint16_t udplen = ntohs(*(uint16_t*)(udp + 4));

            // UDP echo (port 7)
            if (dst_port == 7 && udplen >= 8) {
                // swap MACs
                for (int i = 0; i < 6; i++) { uint8_t t = buf[i]; buf[i] = buf[6+i]; buf[6+i] = t; }
                // swap IPs
                *(uint32_t*)(ip+12) = dst_ip;
                *(uint32_t*)(ip+16) = src_ip;
                // swap ports
                *(uint16_t*)(udp)   = htons(7);
                *(uint16_t*)(udp+2) = htons(src_port);
                // recompute UDP checksum with pseudo-header
                uint8_t pseudo[12 + MAX_PACKET_SIZE];
                memcpy(pseudo, ip+12, 8);   // src,dst
                pseudo[8] = 0; pseudo[9] = 17;
                memcpy(pseudo+10, udp+4, 2);
                memcpy(pseudo+12, udp, udplen);
                *(uint16_t*)(udp+6) = 0;
                *(uint16_t*)(udp+6) = checksum(pseudo, 12 + udplen);
                // recalc IP total-length and checksum
                *(uint16_t*)(ip+2) = htons(ihl + udplen);
                *(uint16_t*)(ip+10) = 0;
                *(uint16_t*)(ip+10) = checksum(ip, ihl);
                // append
                struct iovec iov[2] = { {&ph, sizeof(ph)}, {buf, caplen} };
                writev(fd_out, iov, 2);
                fprintf(stderr, "[twig] Replied to UDP echo\n");
            }
            
            // Time protocol (port 37)
            else if (dst_port == 37) {
                // swap MACs
                for (int i = 0; i < 6; i++) { uint8_t t = buf[i]; buf[i] = buf[6+i]; buf[6+i] = t; }
                // swap IPs
                *(uint32_t*)(ip+12) = dst_ip;
                *(uint32_t*)(ip+16) = src_ip;
                // write timestamp after UDP header
                uint32_t ts1900 = htonl((uint32_t)(time(NULL) + 2208988800U));
                // adjust UDP header
                *(uint16_t*)(udp)   = htons(37);
                *(uint16_t*)(udp+2) = htons(src_port);
                uint16_t newlen = sizeof(uint16_t)*4 + sizeof(ts1900);
                *(uint16_t*)(udp+4) = htons(newlen);
                memcpy(udp + 8, &ts1900, sizeof(ts1900));
                // recompute checksum
                uint8_t pseudo2[12 + MAX_PACKET_SIZE];
                memcpy(pseudo2, ip+12, 8);
                pseudo2[8] = 0; pseudo2[9] = 17;
                memcpy(pseudo2+10, udp+4, 2);
                memcpy(pseudo2+12, udp, newlen);
                *(uint16_t*)(udp+6) = 0;
                *(uint16_t*)(udp+6) = checksum(pseudo2, 12 + newlen);
                // recalc IP
                *(uint16_t*)(ip+2) = htons(ihl + newlen);
                *(uint16_t*)(ip+10) = 0;
                *(uint16_t*)(ip+10) = checksum(ip, ihl);
                // append
                struct pcap_pkthdr ph2 = ph;
                if (swap_endian) {
                    uint32_t c = htons(ETHER_HDR_LEN + ihl + newlen);
                    ph2.caplen = ph2.len = c;
                } else {
                    uint32_t c = ETHER_HDR_LEN + ihl + newlen;
                    ph2.caplen = ph2.len = c;
                }
                struct iovec iov2[2] = { {&ph2, sizeof(ph2)}, {buf, ETHER_HDR_LEN + ihl + newlen} };
                writev(fd_out, iov2, 2);
                fprintf(stderr, "[twig] Replied to Time request\n");
            }
        }
    }

    close(fd_in);
    close(fd_out);
    return 0;
}
