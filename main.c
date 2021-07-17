/*
    Not yet completed, in development.
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ethhdr; /* Ethernet Header */
    struct ip *iphdr;            /* IP Header */

    /* ERROR HERE !!! SEGMENTATION FAULT
    int *count = (int *)args;
    printf("\t[%d]Packet\n", ++(*count));
    */

    printf("\t[*]Recieved Packet Size: [%d]\n", header->len);
    printf("\t[*]Recieved at %s", ctime((const time_t *)&header->ts.tv_sec));

    /* Ethernet Header */
    ethhdr = (struct ether_header *)(packet);
    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP)
    {
        printf("\t[*]Ethernet type Hex:%x  Dec:%d == IP Packet\n", ntohs(ethhdr->ether_type), ntohs(ethhdr->ether_type));
    }
    else if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP)
    {
        printf("\t[*]Ethernet type Hex:%x  Dec:%d == ARP Packet\n", ntohs(ethhdr->ether_type), ntohs(ethhdr->ether_type));
    }
    else
    {
        printf("\t[*]Ethernet type %x not IP\n", ntohs(ethhdr->ether_type));
        exit(1);
    }
    printf("\t%-30s %s\n", "[*]Source MAC Address. . . . .", ether_ntoa((const struct ether_addr *)ethhdr->ether_shost));
    printf("\t%-30s %s\n", "[*]Destination MAC Address . .", ether_ntoa((const struct ether_addr *)ethhdr->ether_dhost));

    /* IP Header */
    iphdr = (struct ip *)(packet + ETHER_HDR_LEN);
    printf("\t%-30s %s\n", "[*]Source IP Address . . . . .", inet_ntoa(iphdr->ip_src));
    printf("\t%-30s %s\n\n", "[*]Destination IP Address. . .", inet_ntoa(iphdr->ip_dst));
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    pcap_if_t *dev;                /* NIC Device */
    pcap_t *handle;                /* Session Handle */
    bpf_u_int32 net, mask;         /* Our IP and Subnet Mask */
    char *netp, *maskp;            /* xxx.xxx.xxx.xxx Notation */
    struct in_addr addr;

    /* Define device */
    if (argc == 2)
    {
        dev->name = argv[1]; /* ERROR HERE !!! SEGMENTATION FAULT !!! */
    }
    else
    {
        if (pcap_findalldevs(&dev, errbuf) == -1)
        {
            fprintf(stderr, "[!]Couldn't find any devices: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    printf("[+]Device: %s\n", dev->name);

    /* Get device's network number and mask */
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "[!]Can't get netmask for device %s\n", dev->name);
        net = 0;
        mask = 0;
    }
    addr.s_addr = net;
    netp = inet_ntoa(addr);
    printf("IP: %s\n", netp);

    addr.s_addr = mask;
    maskp = inet_ntoa(addr);
    printf("Subnet Mask: %s\n", maskp);

    /* Open the device for sniffing */
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "[!]Couldn't open device %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /*  if no packets are currently available to be read, */
    /*  return 0 immediately rather than blocking waiting for packets to arrive. */
    pcap_setnonblock(handle, 1, errbuf);

    /* Loop forever & call processPacket() for every received packet */
    if (pcap_loop(handle, -1, processPacket, NULL) == -1)
    {
        fprintf(stderr, "[!]Loop error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);

    return 0;
}
