/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "dns.h"
#include "qname_table.h"
#include "pcap.h"
#include "common.h"
#include "args.h"
#include "conn.h"

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m);

// PCAP connection generator
void tcp_open_pcap(unsigned portid, struct app_config *app_config) {
    struct rte_mbuf *syn_mbuf = mbuf_clone(pcap_list_get(&app_config->pcap_list));
    syn_mbuf->pkt_len = syn_mbuf->data_len = SYN_MBUF_DATALEN;

    // Fix IP header
    struct ipv4_hdr *ip = mbuf_ip4_ptr(syn_mbuf);
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;

    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // Set-up TCP header
    struct tcp_hdr *tcp = mbuf_tcp_ptr(syn_mbuf);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, syn_mbuf);
    app_config->port_stats[portid].tx_bytes += SYN_MBUF_DATALEN + 24;
    app_config->port_stats[portid].tx_packets++;
}

// QNAME table connection generator
void tcp_open_qname_table(unsigned portid, struct app_config *app_config) {

    uint16_t src_port = rte_rand();
    uint16_t src_ip_rand_octets;

    do {
        src_ip_rand_octets = rte_rand() & app_config->cmdline_args.src_ip_client_mask;
    } while (unlikely(
            src_ip_rand_octets == 0 ||
            src_ip_rand_octets == app_config->cmdline_args.src_ip_client_mask)); // No net and broadcast addrs


    struct rte_mbuf *syn_mbuf = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (syn_mbuf == NULL) {
        RTE_LOG(CRIT, TCPGEN, "failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    syn_mbuf->pkt_len = syn_mbuf->data_len = SYN_MBUF_DATALEN;

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(syn_mbuf);
    memcpy(&eth->d_addr.addr_bytes[0], &app_config->cmdline_args.dst_mac[0], ETHER_ADDR_LEN);
    memcpy(&eth->s_addr.addr_bytes[0], &app_config->cmdline_args.src_mac[0], ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    // Initialize L3 header
    struct ipv4_hdr *ip = mbuf_ip4_ptr(syn_mbuf);
    ip->version_ihl = 0x45; // Version 4 HL 20 (multiplier 5)
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = rte_cpu_to_be_16(0x4000); // Don't fragment flag set
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = rte_cpu_to_be_32(*((uint32_t *) app_config->cmdline_args.src_ip_net) | src_ip_rand_octets);
    ip->dst_addr = rte_cpu_to_be_32(*((uint32_t *) app_config->cmdline_args.dst_ip));

    // Process IP checksum
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // Initialize L4 header
    struct tcp_hdr *tcp = mbuf_tcp_ptr(syn_mbuf);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(DNS_PORT);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Process TCP checksum
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, syn_mbuf);
    app_config->port_stats[portid].tx_bytes += SYN_MBUF_DATALEN + 24;
    app_config->port_stats[portid].tx_packets++;
}

void send_ack(struct rte_mbuf *m, unsigned portid, struct app_config *app_config, bool fin) {
    // Pointers to headers
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);

    uint8_t data_offset = tcp->data_off; // data_off * 4 = byte offset
    int16_t payload_len = rte_be_to_cpu_16(ip->total_length) - sizeof(struct ipv4_hdr) - (data_offset >> 2);

    m->pkt_len = m->data_len = ACK_MBUF_DATALEN;

    // Swap MAC addresses
    *((uint64_t *) &eth->d_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->s_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;
    *((uint64_t *) &eth->s_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->d_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;
    *((uint64_t *) &eth->d_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->s_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;

    // Swap IP addresses
    ip->src_addr ^= ip->dst_addr;
    ip->dst_addr ^= ip->src_addr;
    ip->src_addr ^= ip->dst_addr;

    ip->packet_id = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->hdr_checksum = 0;

    // Update TCP header
    tcp->src_port ^= tcp->dst_port;
    tcp->dst_port ^= tcp->src_port;
    tcp->src_port ^= tcp->dst_port;

    tcp->sent_seq ^= tcp->recv_ack;
    tcp->recv_ack ^= tcp->sent_seq;
    tcp->sent_seq ^= tcp->recv_ack;

    if (payload_len > 0)
        tcp->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->recv_ack) + payload_len);
    else
        tcp->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->recv_ack) + 1); // ACK sender's seq +1

    tcp->tcp_flags = 0x10; // set ACK
    if (fin)
        tcp->tcp_flags |= 0x01;

    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->cksum = 0;

    // Update cksums
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, m);
    app_config->port_stats[portid].tx_bytes += ACK_MBUF_DATALEN;
    app_config->port_stats[portid].tx_packets++;
}

void generate_query_pcap(struct rte_mbuf *m, unsigned portid, struct app_config *app_config)
{
    struct rte_mbuf *ref_query = pcap_list_get(&app_config->pcap_list);
    void *ref_data = mbuf_dns_header_ptr(ref_query);

    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);

    m->pkt_len = m->data_len = ref_query->data_len;

}

void generate_query(struct rte_mbuf *m, unsigned portid) {
    // Select random QNAME from table
    uint32_t qname_index = rte_rand() % qname_table.records;
    uint8_t qname_bytes = qname_table.data[qname_index].qname_bytes;

    // Pointers to headers
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);
    struct dns_hdr *dns_hdr = mbuf_dns_header_ptr(m);
    uint8_t *qname_ptr = mbuf_dns_qname_ptr(m);
    struct dns_query_flags *dns_query_flags = (struct dns_query_flags *) (qname_ptr + qname_bytes);

    m->pkt_len = m->data_len = DNS_PACKET_MIN_LEN + qname_bytes + sizeof(struct dns_query_flags);

    ip->total_length = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr));
    ip->hdr_checksum = 0;

    tcp->tcp_flags = 0x18; // ACK + PSH
    tcp->cksum = 0;

    dns_hdr->len = rte_cpu_to_be_16(
            sizeof(struct dns_hdr) + qname_bytes + sizeof(struct dns_query_flags) - 2); // Length bytes not counted
    dns_hdr->tx_id = rte_rand();
    dns_hdr->flags = 0;
    dns_hdr->q_cnt = rte_cpu_to_be_16(1);
    dns_hdr->an_cnt = 0;
    dns_hdr->auth_cnt = 0;
    dns_hdr->additional_cnt = 0;

    memcpy(qname_ptr, qname_table.data[qname_index].qname, qname_bytes);

    dns_query_flags->qtype = rte_cpu_to_be_16(DNS_QTYPE_A);
    dns_query_flags->qclass = rte_cpu_to_be_16(DNS_QCLASS_IN);

    // Update cksums
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, m);
    port_stats[portid].tx_bytes += m->data_len;
    port_stats[portid].tx_packets++;
    port_stats[portid].tx_queries++;
}

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m) {
    struct rte_mbuf *clone = rte_pktmbuf_alloc(tcpgen_pktmbuf_pool);
    if (clone == NULL)
        rte_exit(EXIT_FAILURE, "mbuf clone - mbuf alloc failed\n");

    clone->pkt_len = clone->data_len = m->data_len;
    rte_memcpy(rte_pktmbuf_mtod(clone, void *), rte_pktmbuf_mtod(m, const void *), m->data_len);

    return clone;
}

static void response_classify(struct rte_mbuf *m, unsigned portid) {
    struct dns_hdr *dns_hdr = mbuf_dns_header_ptr(m);
    uint8_t rcode = rte_be_to_cpu_16(dns_hdr->flags) & 0xf;
    port_stats[portid].rx_rcode[rcode]++;
}

// Incoming packet handler
static void
handle_incoming(struct rte_mbuf *m, unsigned portid) {

    port_stats[portid].rx_bytes += m->pkt_len;

    // Ensure that at least Ethernet, IP and TCP headers are present
    if (m->pkt_len < SYN_MBUF_DATALEN) {
        rte_pktmbuf_free(m);
        return;
    }

    // Pointers to headers
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);

    // Discard non-DNS traffic
    if (rte_be_to_cpu_16(eth->ether_type) != ETHER_TYPE_IPv4) {
        rte_pktmbuf_free(m);
        return;
    }

    if (ip->next_proto_id != IPPROTO_TCP) {
        rte_pktmbuf_free(m);
        return;
    }

    if (rte_be_to_cpu_16(tcp->src_port) != DNS_PORT) {
        rte_pktmbuf_free(m);
        return;
    }

    // If this is a SYN-ACK, generate ACK and DNS query
    if ((tcp->tcp_flags & 0x12) == 0x12) {
        rte_mbuf_refcnt_update(m, 1); // Keep mbuf for cloning into query
        send_ack(m, portid, false);
        struct rte_mbuf *m_clone = mbuf_clone(m);
        rte_mbuf_refcnt_update(m, -1);
        generate_query(m_clone, portid);
    }
        // Generate ACK if SYN or FIN is set
    else if (tcp->tcp_flags & 0x03) {
        send_ack(m, portid, false);
    }
        // Handle DNS query response
    else if (m->pkt_len > DNS_PACKET_MIN_LEN) {
        port_stats[portid].rx_responses++;
        rte_mbuf_refcnt_update(m, 1); // Keep mbuf for RCODE classification
        send_ack(m, portid, true);
        response_classify(m, portid);
        rte_mbuf_refcnt_update(m, -1);
    } else {
        rte_pktmbuf_free(m);
    }
}