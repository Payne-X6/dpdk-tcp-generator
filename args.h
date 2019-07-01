//
// Created by postolka on 1.7.19.
//

#ifndef DPDK_TCP_GENERATOR_ARGS_H
#define DPDK_TCP_GENERATOR_ARGS_H

#include "common.h"

#define ARG_SRC_MAC (1 << 0)
#define ARG_DST_MAC (1 << 1)
#define ARG_SRC_SUBNET (1 << 2)
#define ARG_DST_IP (1 << 3)
#define ARG_PORT_MASK (1 << 4)
#define ARG_QNAME_FILE (1 << 5)
#define ARG_TSC_PERIOD (1 << 6)
#define ARG_PCAP_FILE (1 << 7)

#define ARG_REQUIRED (ARG_SRC_MAC | ARG_DST_MAC | ARG_SRC_SUBNET | ARG_DST_IP | ARG_PORT_MASK | ARG_QNAME_FILE)

void tcpgen_usage(const char *prgname);
int tcpgen_parse_args(int argc, char **argv, struct cmdline_args *args);

#endif //DPDK_TCP_GENERATOR_ARGS_H
