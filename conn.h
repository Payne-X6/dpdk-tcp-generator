//
// Created by postolka on 1.7.19.
//

#ifndef DPDK_TCP_GENERATOR_CONN_H
#define DPDK_TCP_GENERATOR_CONN_H

#define SYN_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv4_hdr) + \
    sizeof(struct tcp_hdr) )
#define ACK_MBUF_DATALEN SYN_MBUF_DATALEN
#define MIN_PKT_LEN SYN_MBUF_DATALEN
#define DNS_PACKET_MIN_LEN (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + sizeof(struct dns_hdr))

#endif //DPDK_TCP_GENERATOR_CONN_H
