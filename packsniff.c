#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); // skip ethernet header (14 bytes)
    printf("Captured Packet: Src IP: %s -> Dst IP: %s\n",
           inet_ntoa(ip_header->ip_src),
           inet_ntoa(ip_header->ip_dst));
}

int main() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find device: %s\n", errbuf);
        return 1;
    }
    printf("Sniffing on device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
