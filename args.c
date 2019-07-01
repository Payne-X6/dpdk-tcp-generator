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
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include "qname_table.h"
#include "pcap.h"
#include "common.h"
#include "args.h"

void tcpgen_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK [-t TCP GAP] -f QNAME file --src-mac SRC_MAC --dst-mac DST_MAC --src-subnet SRC_SUBNET --dst-ip DST_IP\n"
           "  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on\n"
           "  -t TCP GAP: TSC delay before opening a new TCP connection\n"
           "  -f QNAME file: File containing a list of QNAMEs used for generating queries\n"
           "  --src-mac: Source MAC address of queries\n"
           "  --dst-mac: Destination MAC address of queries\n"
           "  --src-subnet: Source subnet of queries (for example 10.10.0.0/16)\n"
           "  --dst-ip: Destination IP of queries\n",
           prgname);
}

static int tcpgen_parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static const char short_options[] =
        "p:"  // portmask
        "t:"  // tcp gap
        "f:"  // QNAME file
;

#define CMD_LINE_OPT_SRC_MAC "src-mac"
#define CMD_LINE_OPT_DST_MAC "dst-mac"
#define CMD_LINE_OPT_SRC_SUBNET "src-subnet"
#define CMD_LINE_OPT_DST_IP "dst-ip"
#define CMD_LINE_OPT_PCAP_FILE "pcap"

enum {
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_SRC_MAC_NUM,
    CMD_LINE_OPT_DST_MAC_NUM,
    CMD_LINE_OPT_SRC_SUBNET_NUM,
    CMD_LINE_OPT_DST_IP_NUM,
    CMD_LINE_OPT_PCAP_FILE_NUM,
};

static const struct option long_options[] = {
        {CMD_LINE_OPT_SRC_MAC,    required_argument, 0, CMD_LINE_OPT_SRC_MAC_NUM},
        {CMD_LINE_OPT_DST_MAC,    required_argument, 0, CMD_LINE_OPT_DST_MAC_NUM},
        {CMD_LINE_OPT_SRC_SUBNET, required_argument, 0, CMD_LINE_OPT_SRC_SUBNET_NUM},
        {CMD_LINE_OPT_DST_IP,     required_argument, 0, CMD_LINE_OPT_DST_IP_NUM},
        {CMD_LINE_OPT_PCAP_FILE,  required_argument, 0, CMD_LINE_OPT_PCAP_FILE_NUM},
        {NULL, 0,                                    0, 0}
};


int tcpgen_parse_args(int argc, char **argv, struct cmdline_args *args) {
    int opt, ret;
    int option_index;
    int scanned;
    char **argvopt;
    char *prgname = argv[0];

    uint8_t src_ip_cidr;

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
            case 'p':
                args->enabled_port_mask = tcpgen_parse_portmask(optarg);
                if (args->enabled_port_mask == 0) {
                    printf("invalid portmask\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                args->supplied_args |= ARG_PORT_MASK;
                break;

            case 't':
                args->tx_tsc_period = strtoull(optarg, NULL, 10);
                args->supplied_args |= ARG_TSC_PERIOD;
                break;

            case 'f':
                args->qname_file = optarg;
                args->supplied_args |= ARG_QNAME_FILE;
                break;

            case CMD_LINE_OPT_SRC_MAC_NUM:
                scanned = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                 &args->src_mac[0],
                                 &args->src_mac[1],
                                 &args->src_mac[2],
                                 &args->src_mac[3],
                                 &args->src_mac[4],
                                 &args->src_mac[5]
                );
                if (scanned != ETHER_ADDR_LEN) {
                    fprintf(stderr, "failed to parse src-mac\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                args->supplied_args |= ARG_SRC_MAC;
                break;

            case CMD_LINE_OPT_DST_MAC_NUM:
                scanned = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                 &args->dst_mac[0],
                                 &args->dst_mac[1],
                                 &args->dst_mac[2],
                                 &args->dst_mac[3],
                                 &args->dst_mac[4],
                                 &args->dst_mac[5]
                );
                if (scanned != ETHER_ADDR_LEN) {
                    fprintf(stderr, "failed to parse dst-mac\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                args->supplied_args |= ARG_DST_MAC;
                break;

            case CMD_LINE_OPT_SRC_SUBNET_NUM:
                // little-endian int casting
                scanned = sscanf(optarg, "%hhd.%hhd.%hhd.%hhd/%hhd",
                                 &args->src_ip_net[3],
                                 &args->src_ip_net[2],
                                 &args->src_ip_net[1],
                                 &args->src_ip_net[0],
                                 &src_ip_cidr
                );
                if (scanned != IPv4_ADDR_LEN + 1) {
                    fprintf(stderr, "failed to parse src subnet\n");
                    tcpgen_usage(prgname);
                    return -1;
                }

                args->src_ip_client_mask = (1 << (32 - src_ip_cidr)) - 1;
                args->supplied_args |= ARG_SRC_SUBNET;
                break;

            case CMD_LINE_OPT_DST_IP_NUM:
                // little-endian int casting
                scanned = sscanf(optarg, "%hhd.%hhd.%hhd.%hhd",
                                 &args->dst_ip[3],
                                 &args->dst_ip[2],
                                 &args->dst_ip[1],
                                 &args->dst_ip[0]
                );
                if (scanned != IPv4_ADDR_LEN) {
                    fprintf(stderr, "failed to parse dest IP\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                args->supplied_args |= ARG_DST_IP;
                break;

            case CMD_LINE_OPT_PCAP_FILE_NUM:
                args->pcap_file = optarg;
                args->supplied_args |= ARG_PCAP_FILE;
                break;

            default:
                tcpgen_usage(prgname);
                return -1;
        }
    }

    if (((args->supplied_args & ARG_REQUIRED) != ARG_REQUIRED) && !(args->supplied_args & ARG_PCAP_FILE)) {
        // Missing required arguments
        fprintf(stderr, "must supply required arguments or PCAP file\n");
        tcpgen_usage(prgname);
        return -1;
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; // reset getopt lib
    return ret;
}