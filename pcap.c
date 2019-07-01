/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "pcap.h"
#include "common.h"

#define MAGIC_USEC_TS 0xa1b2c3d4
#define MAGIC_NSEC_TS 0xa1b23c4d

void pcap_list_init(struct pcap_list *list)
{
    list->first = list->current = list->last = NULL;
}

static void pcap_list_insert(struct pcap_list *list, struct rte_mbuf *mbuf)
{
    struct pcap_list_entry *new_entry = rte_zmalloc("pcap_list_entry", sizeof(struct pcap_list_entry), 0);
    if(new_entry == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc failed (pcap_list_entry)\n");
    }

    new_entry->mbuf = mbuf;
    new_entry->next = NULL;

    if(list->first == NULL) {
        list->first = list->last = list->current = new_entry;
    }
    else {
        list->last->next = new_entry;
        list->last = new_entry;
    }
}

struct rte_mbuf * pcap_list_get(const struct pcap_list *list)
{
    struct pcap_list_entry *current = list->current;

    if(current == NULL) {
        return NULL;
    }

    return current->mbuf;
}

void pcap_list_next(struct pcap_list *list)
{
    if(list->current == NULL)
        return;

    if(list->current->next == NULL)
        list->current = list->first;
    else
        list->current = list->current->next;
}

void pcap_list_destroy(struct pcap_list *list)
{
    struct pcap_list_entry *next;
    struct pcap_list_entry *current;

    for(current = list->first; current != NULL;) {
        next = current->next;
        rte_free(current);
        current = next;
    }

    list->first = list->current = list->last = NULL;
}

void pcap_parse(const char *filename, struct rte_mempool *pktmbuf_pool, struct pcap_list *pcap_list)
{
    FILE *fp = fopen(filename, "r");
    if(fp == NULL) {
        rte_exit(EXIT_FAILURE, "failed to open pcap file\n");
    }

    struct pcap_global_hdr hdr;
    if(fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        rte_exit(EXIT_FAILURE, "failed to read PCAP header\n");
    }

    if(hdr.magic_number != MAGIC_USEC_TS && hdr.magic_number != MAGIC_NSEC_TS) {
        rte_exit(EXIT_FAILURE, "invalid or unsupported PCAP magic\n");
    }

    struct pcap_packet_hdr pkt_hdr;

    size_t pcap_bytes = 0;
    uint32_t pcap_records = 0;
    while(fread(&pkt_hdr, sizeof(pkt_hdr), 1, fp) == 1) {
        struct ether_hdr eth_hdr;
        struct ipv4_hdr ip_hdr;
        struct udp_hdr udp_hdr;

        uint32_t read_bytes = 0;

        if(fread(&eth_hdr, sizeof(eth_hdr), 1, fp) != 1) {
            rte_exit(EXIT_FAILURE, "pcap: failed to read ether header\n");
        }

        read_bytes += sizeof(eth_hdr);

        if(rte_be_to_cpu_16(eth_hdr.ether_type) != ETHER_TYPE_IPv4) {
            rte_exit(EXIT_FAILURE, "pcap: unsupported ether type\n");
        }

        if(fread(&ip_hdr, sizeof(ip_hdr), 1, fp) != 1) {
            rte_exit(EXIT_FAILURE, "pcap: failed to read ipv4 header\n");
        }

        read_bytes += sizeof(ip_hdr);

        if(ip_hdr.next_proto_id != IPPROTO_UDP) {
            rte_exit(EXIT_FAILURE, "pcap: unsupported non-UDP next_proto_id in IP header\n");
        }

        if(fread(&udp_hdr, sizeof(udp_hdr), 1, fp) != 1) {
            rte_exit(EXIT_FAILURE, "pcap: failed to read UDP header\n");
        }

        read_bytes += sizeof(udp_hdr);

        struct rte_mbuf *pcap_mbuf = rte_pktmbuf_alloc(pktmbuf_pool);
        if(pcap_mbuf == NULL) {
            rte_exit(EXIT_FAILURE, "pcap: mbuf allocation failed\n");
        }

        pcap_mbuf->pkt_len = pcap_mbuf->data_len = pkt_hdr.incl_len;
        struct ether_hdr *mbuf_eth = mbuf_eth_ptr(pcap_mbuf);
        struct ipv4_hdr *mbuf_ip = mbuf_ip4_ptr(pcap_mbuf);
        struct tcp_hdr *mbuf_tcp = mbuf_tcp_ptr(pcap_mbuf);
        void *mbuf_l7_data = mbuf_dns_header_ptr(pcap_mbuf);

        memcpy(mbuf_eth, &eth_hdr, sizeof(struct ether_hdr));
        memcpy(mbuf_ip, &ip_hdr, sizeof(struct ipv4_hdr));
        memset(mbuf_tcp, 0, sizeof(struct tcp_hdr));

        mbuf_tcp->src_port = udp_hdr.src_port;
        mbuf_tcp->dst_port = udp_hdr.dst_port;

        // Read in rest of mbuf
        int remaining_bytes = pkt_hdr.incl_len - read_bytes;
        if(remaining_bytes <= 0) {
            rte_exit(EXIT_FAILURE, "pcap: invalid l7 payload size\n");
        }

        if(fread(mbuf_l7_data, 1, remaining_bytes, fp) != remaining_bytes) {
            rte_exit(EXIT_FAILURE, "pcap: failed to read l7 payload\n");
        }

        read_bytes += remaining_bytes;

        // Insert mbuf to pcap list
        pcap_list_insert(pcap_list, pcap_mbuf);

        pcap_bytes += read_bytes;
        pcap_records++;
    }
}