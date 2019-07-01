//
// Created by postolka on 25.6.19.
//

#ifndef DPDK_TCP_GENERATOR_COMMON_H
#define DPDK_TCP_GENERATOR_COMMON_H

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

#define RTE_LOGTYPE_TCPGEN RTE_LOGTYPE_USER1

#define mbuf_eth_ptr(m) (rte_pktmbuf_mtod((m), struct ether_hdr *))
#define mbuf_ip4_ptr(m) (rte_pktmbuf_mtod_offset((m), struct ipv4_hdr *, sizeof(struct ether_hdr)))
#define mbuf_tcp_ptr(m) (rte_pktmbuf_mtod_offset((m), struct tcp_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)))
#define mbuf_dns_header_ptr(m) (rte_pktmbuf_mtod_offset((m), struct dns_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr)))
#define mbuf_dns_qname_ptr(m) (rte_pktmbuf_mtod_offset((m), uint8_t *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + sizeof(struct dns_hdr)))

#define DNS_PORT 53
#define IPv4_ADDR_LEN 4

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
    unsigned n_port;
    unsigned port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;

struct port_stats {
    // Total TX packet count
    uint64_t tx_packets;
    // Total TX byte count
    uint64_t tx_bytes;
    // DNS query TX count
    uint64_t tx_queries;
    // TX dropped count
    uint64_t tx_dropped;

    // Total RX packet count
    uint64_t rx_packets;
    // Total RX byte count
    uint64_t rx_bytes;
    // DNS packet RX count
    uint64_t rx_responses;
    // Per-RCode stats
    uint64_t rx_rcode[DNS_RCODE_MAX_TYPES];
} __rte_cache_aligned;

struct app_config;

struct dpdk_config {
    // Number of RX/TX ring descriptors
    uint16_t nb_rxd;
    uint16_t nb_txd;

    // Mask of enabled ports
    uint32_t enabled_port_mask;

    // RX-queues per lcore
    unsigned int rx_queue_per_lcore;

    // per-lcore queue configurations
    struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

    // per-port TX buffers
    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

    // Universal port configuration
    struct rte_eth_conf port_conf;

    // mbuf mempool
    struct rte_mempool *pktmbuf_pool;
};

struct user_config {
    // TSC period for query generation
    uint64_t tx_tsc_period;

    // QNAME table
    struct qname_table qname_table;

    // PCAP list
    struct pcap_list pcap_list;

    // Packet parameters
    uint8_t src_mac[ETHER_ADDR_LEN];
    uint8_t dst_mac[ETHER_ADDR_LEN];
    uint8_t src_ip_net[IPv4_ADDR_LEN];
    uint8_t dst_ip[IPv4_ADDR_LEN];
    uint32_t src_ip_client_mask;

    // Functions used for generating traffic
    void (*f_tcp_open)(unsigned, struct app_config *);
};

struct cmdline_args {
    uint32_t enabled_port_mask;
    uint64_t tx_tsc_period;
    const char *qname_file;
    const char *pcap_file;
    uint8_t src_mac[ETHER_ADDR_LEN];
    uint8_t dst_mac[ETHER_ADDR_LEN];
    uint8_t src_ip_net[IPv4_ADDR_LEN];
    uint8_t dst_ip[IPv4_ADDR_LEN];
    uint32_t src_ip_client_mask;

    uint32_t supplied_args;
};

struct app_config {
    struct dpdk_config dpdk_config;

    struct port_stats port_stats[RTE_MAX_ETHPORTS];

    struct cmdline_args cmdline_args;

    struct qname_table qname_table;
    struct pcap_list pcap_list;
};

#endif //DPDK_TCP_GENERATOR_COMMON_H
