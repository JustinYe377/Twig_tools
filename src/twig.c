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
// IPv4 header
struct ip_hdr {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};
// ICMP header
struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};
// UDP header
struct udp_hdr {
    uint16_t source;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
};
// Compute checksum for IP/ICMP/UDP
static uint16_t checksum(void *vdata, size_t length) {
    uint8_t *data = vdata;
    uint32_t sum = 0;
    while (length > 1) {
        sum += (data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }
    if (length == 1) sum += data[0] << 8;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

int main(int argc, char *argv[]) {
    char *iface_spec = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "i:")) != -1) {
        if (opt == 'i') iface_spec = optarg;
        else {
            fprintf(stderr, "Usage: %s -i <address_prefix>\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (!iface_spec) {
        fprintf(stderr, "Usage: %s -i <address_prefix>\n", argv[0]);
        return EXIT_FAILURE;
    }
    char addr_str[INET_ADDRSTRLEN];
    int prefix;
    if (sscanf(iface_spec, "%15[^_]_%d", addr_str, &prefix) != 2) {
        fprintf(stderr, "Invalid interface spec: %s. Expected A.B.C.D_P\n", iface_spec);
        return EXIT_FAILURE;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, addr_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", addr_str);
        return EXIT_FAILURE;
    }
    uint32_t host = ntohl(addr.s_addr);
    uint32_t mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    uint32_t net = host & mask;
    struct in_addr net_addr;
    net_addr.s_addr = htonl(net);
    char net_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &net_addr, net_str, sizeof(net_str))) {
        perror("inet_ntop");
        return EXIT_FAILURE;
    }
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "%s_%d.dmp", net_str, prefix);
    fprintf(stderr, "[twig] Using pcap file: %s\n", fname);

    int fd_in = open(fname, O_RDONLY);
    int fd_out = open(fname, O_RDWR | O_APPEND);
    if (fd_in < 0 || fd_out < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    struct pcap_file_header gh;
    if (read(fd_in, &gh, sizeof(gh)) != sizeof(gh)) {
        fprintf(stderr, "Failed to read global header\n");
        return EXIT_FAILURE;
    }
    int swap_endian = (gh.magic == 0xd4c3b2a1);
    if (!swap_endian && gh.magic != 0xa1b2c3d4) {
        fprintf(stderr, "Unknown pcap magic: %08x\n", gh.magic);
        return EXIT_FAILURE;
    }

    struct pcap_pkthdr ph;
    uint8_t buffer[MAX_PACKET_SIZE];

    // Real-time follow: loop and wait for new packets
    while (1) {
        ssize_t rh = read(fd_in, &ph, sizeof(ph));
        if (rh == 0) {
            // No new header yet, sleep briefly
            usleep(10000);
            continue;
        }
        if (rh < 0) {
            perror("read header");
            break;
        }
        if (rh != sizeof(ph)) {
            // Partial read, skip
            continue;
        }
        uint32_t caplen = swap_endian ? ntohl(ph.caplen) : ph.caplen;
        if (caplen > MAX_PACKET_SIZE) {
            lseek(fd_in, caplen, SEEK_CUR);
            continue;
        }
        ssize_t rd = read(fd_in, buffer, caplen);
        if (rd < caplen) {
            // Incomplete packet, skip
            continue;
        }
        // Parse Ethernet
        uint16_t ethertype = ntohs(*(uint16_t*)(buffer + 12));
        if (ethertype != 0x0800) continue;
        struct ip_hdr *ip = (struct ip_hdr*)(buffer + ETHER_HDR_LEN);
        int iphlen = ip->ihl * 4;
        if (iphlen < sizeof(struct ip_hdr)) continue;
        // ICMP
        if (ip->protocol == 1) {
            struct icmp_hdr *icmp = (struct icmp_hdr*)(buffer + ETHER_HDR_LEN + iphlen);
            if (icmp->type == 8) {
                // Swap MACs
                for (int i = 0; i < 6; i++) {
                    uint8_t t = buffer[i]; buffer[i] = buffer[6+i]; buffer[6+i] = t;
                }
                // Swap IPs
                uint32_t t_ip = ip->saddr; ip->saddr = ip->daddr; ip->daddr = t_ip;
                // Reply
                icmp->type = 0;
                icmp->checksum = 0;
                uint32_t icmplen = caplen - ETHER_HDR_LEN - iphlen;
                icmp->checksum = checksum(icmp, icmplen);
                ip->checksum = 0;
                ip->checksum = checksum(ip, iphlen);
                struct iovec iov[2] = {{&ph, sizeof(ph)}, {buffer, caplen}};
                writev(fd_out, iov, 2);
                fprintf(stderr, "[twig] Replied to ICMP echo request\n");
            }
            continue;
        }
        // UDP
        if (ip->protocol == 17) {
            struct udp_hdr *udp = (struct udp_hdr*)(buffer + ETHER_HDR_LEN + iphlen);
            uint16_t src_port = ntohs(udp->source);
            uint16_t dst_port = ntohs(udp->dest);
            // Echo (7)
            if (dst_port == 7) {
                for (int i = 0; i < 6; i++) {
                    uint8_t t = buffer[i]; buffer[i] = buffer[6+i]; buffer[6+i] = t;
                }
                uint32_t t_ip = ip->saddr; ip->saddr = ip->daddr; ip->daddr = t_ip;
                udp->source = htons(7);
                udp->dest = htons(src_port);
                uint32_t udplen = ntohs(udp->length);
                udp->checksum = 0;
                udp->checksum = checksum(udp, udplen);
                ip->tot_len = htons(iphlen + udplen);
                ip->checksum = 0;
                ip->checksum = checksum(ip, iphlen);
                struct iovec iov[2] = {{&ph, sizeof(ph)}, {buffer, caplen}};
                writev(fd_out, iov, 2);
                fprintf(stderr, "[twig] Replied to UDP echo\n");
                continue;
            }
            // Time (37)
            if (dst_port == 37) {
                for (int i = 0; i < 6; i++) {
                    uint8_t t = buffer[i]; buffer[i] = buffer[6+i]; buffer[6+i] = t;
                }
                uint32_t t_ip = ip->saddr; ip->saddr = ip->daddr; ip->daddr = t_ip;
                uint32_t ts1900 = htonl((uint32_t)(time(NULL) + 2208988800U));
                struct udp_hdr *u2 = (struct udp_hdr*)(buffer + ETHER_HDR_LEN + iphlen);
                u2->source = htons(37);
                u2->dest = htons(src_port);
                uint16_t newudplen = sizeof(*u2) + sizeof(ts1900);
                u2->length = htons(newudplen);
                memcpy((uint8_t*)(u2 + 1), &ts1900, sizeof(ts1900));
                u2->checksum = 0;
                u2->checksum = checksum(u2, newudplen);
                ip->tot_len = htons(iphlen + newudplen);
                ip->checksum = 0;
                ip->checksum = checksum(ip, iphlen);
                struct pcap_pkthdr ph2 = ph;
                uint32_t newcap = ETHER_HDR_LEN + iphlen + newudplen;
                if (swap_endian) ph2.caplen = ph2.len = htonl(newcap);
                else ph2.caplen = ph2.len = newcap;
                struct iovec iov[2] = {{&ph2, sizeof(ph2)}, {buffer, newcap}};
                writev(fd_out, iov, 2);
                fprintf(stderr, "[twig] Replied to Time request\n");
                continue;
            }
        }
    }
    close(fd_in);
    close(fd_out);
    return EXIT_SUCCESS;
}

