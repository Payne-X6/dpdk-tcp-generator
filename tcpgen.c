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

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static struct dpdk_config dpdk_default_config = {
        .nb_rxd = RTE_TEST_RX_DESC_DEFAULT,
        .nb_txd = RTE_TEST_TX_DESC_DEFAULT,
        .enabled_port_mask = 0,
        .rx_queue_per_lcore = 1,
        .port_conf = {
                .rxmode = {
                        .split_hdr_size = 0,
                },
                .txmode = {
                        .mq_mode = ETH_MQ_TX_NONE,
                },
        },
        .pktmbuf_pool = NULL,
};

static volatile bool force_quit;



#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 // TX drain every ~100us
#define MEMPOOL_CACHE_SIZE 256

static void
tcpgen_main_loop(struct app_config *app_config) {
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, tx_tsc, tx_diff;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
                               BURST_TX_DRAIN_US;
    struct rte_eth_dev_tx_buffer *buffer;
    uint64_t start_tsc, stop_tsc;

    prev_tsc = 0;
    tx_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &app_config->dpdk_config.lcore_queue_conf[lcore_id];

    if (qconf->n_port == 0) {
        RTE_LOG(INFO, TCPGEN, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, TCPGEN, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_port; i++) {

        portid = qconf->port_list[i];
        RTE_LOG(INFO, TCPGEN, " -- lcoreid=%u portid=%u\n", lcore_id,
                portid);

    }

    start_tsc = rte_rdtsc();

    while (!force_quit) {
        cur_tsc = rte_rdtsc();

        // TX burst queue drain
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_port; i++) {
                portid = qconf->port_list[i];
                buffer = app_config->dpdk_config.tx_buffer[portid];
                rte_eth_tx_buffer_flush(portid, 0, buffer);
            }
            prev_tsc = cur_tsc;
        }

        // Read packet from RX queues
        tx_diff = cur_tsc - tx_tsc;
        for (i = 0; i < qconf->n_port; i++) {
            portid = qconf->port_list[i];

            if (tx_diff > app_config->user_config.tx_tsc_period) {
                tcp_open(portid);
                tx_tsc = cur_tsc;
            }

            nb_rx = rte_eth_rx_burst(portid, 0,
                                     pkts_burst, MAX_PKT_BURST);

            app_config->port_stats[portid].rx_packets += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                handle_incoming(m, portid);
            }
        }
    }

    for (i = 0; i < qconf->n_port; i++) {
        portid = qconf->port_list[i];
        buffer = app_config->dpdk_config.tx_buffer[portid];
        rte_eth_tx_buffer_flush(portid, 0, buffer);
    }

    stop_tsc = rte_rdtsc();
    uint64_t runtime_tsc = stop_tsc - start_tsc;
    uint64_t runtime_usec = runtime_tsc / (rte_get_tsc_hz() / 1000000);
    uint64_t runtime_sec = runtime_tsc / rte_get_tsc_hz();
    printf("Total runtime: %lu microseconds (%lu seconds)\n", runtime_usec, runtime_sec);
    for (i = 0; i < qconf->n_port; i++) {
        portid = qconf->port_list[i];
        printf("Port %d stats:\n\tTX bytes: %lu\n\tTX packets: %lu\n\tTX queries: %lu\n\n\t",
               portid,
               app_config->port_stats[portid].tx_bytes,
               app_config->port_stats[portid].tx_packets,
               app_config->port_stats[portid].tx_queries);
        printf("RX bytes: %lu\n\tRX packets: %lu\n\tRX responses: %lu\n\t\t",
               app_config->port_stats[portid].rx_bytes,
               app_config->port_stats[portid].rx_packets,
               app_config->port_stats[portid].rx_responses);
        printf("NOERROR: %lu\n\t\tFORMERR: %lu\n\t\tSERVFAIL: %lu\n\t\tNXDOMAIN: %lu\n\t\tNOTIMP: %lu\n\t\tREFUSED: %lu\n\n\t",
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NOERROR],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_FORMERR],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_SERVFAIL],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NXDOMAIN],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NOTIMP],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_REFUSED]);
        printf("TX bitrate: %f Gbit/s\n\tTX QPS: %.2f\n\tTX FPS: %.2f\n\tRX bitrate: %f Gbit/s\n\tRX RPS: %.2f\n\tRX FPS: %.2f\n\tResponse rate: %.2f%%\n",
               ((app_config->port_stats[portid].tx_bytes << 3) / (double) runtime_usec) / 1000,
               (app_config->port_stats[portid].tx_queries / (double) runtime_usec) * 1000000,
               (app_config->port_stats[portid].tx_packets / (double) runtime_usec) * 1000000,
               ((app_config->port_stats[portid].rx_bytes << 3) / (double) runtime_usec) / 1000,
               (app_config->port_stats[portid].rx_responses / (double) runtime_usec) * 1000000,
               (app_config->port_stats[portid].rx_packets / (double) runtime_usec) * 1000000,
               ((app_config->port_stats[portid].rx_responses / (double) app_config->port_stats[portid].tx_queries)) * 100);
    }
}

static int
tcpgen_launch_one_lcore(struct app_config *app_config) {
    tcpgen_main_loop(app_config);
    return 0;
}

// Check the link status of all ports in up to 9s, and print them
static void
check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 // 100ms
#define MAX_CHECK_TIME 90 // 9s (90 * 100ms) in total
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status...");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            // print link status if flag set
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                            "Port%d Link Up. Speed %u Mbps - %s\n",
                            portid, link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            // clear all_ports_up flag if any link down
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        // set the print_flag if all ports up or timeout
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf(" done\n");
        }
    }
}

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        force_quit = true;
    }
}

int
main(int argc, char **argv) {
    struct lcore_queue_conf *qconf;
    int ret;
    uint16_t nb_ports;
    uint16_t nb_ports_available = 0;
    uint16_t portid;
    unsigned lcore_id, rx_lcore_id;
    unsigned nb_ports_in_mask = 0;
    unsigned int nb_lcores = 0;
    unsigned int nb_mbufs;

    // init EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize application config
    struct app_config app_config;
    app_config.dpdk_config = dpdk_default_config;

    // Parse command-line arguments (non-EAL ones)
    memset(&app_config.cmdline_args, 0, sizeof(struct cmdline_args));
    ret = tcpgen_parse_args(argc, argv, &app_config.cmdline_args);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid TCPGEN arguments\n");

    // Create mbuf mempool
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    nb_mbufs = RTE_MAX(nb_ports * (app_config.dpdk_config.nb_rxd + app_config.dpdk_config.nb_txd + MAX_PKT_BURST +
                                   nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

    app_config.dpdk_config.pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
                                                                  MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                                  rte_socket_id());
    if (app_config.dpdk_config.pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


    // Initialize helper structures
    memset(&app_config.qname_table, 0, sizeof(struct qname_table));
    pcap_list_init(&app_config.pcap_list);

    // Initialize QNAME table or PCAP linked-list based on supplied arguments
    if(app_config.cmdline_args.supplied_args & ARG_PCAP_FILE) {
        pcap_parse(app_config.cmdline_args.pcap_file, app_config.dpdk_config.pktmbuf_pool, &app_config.pcap_list);
        // TODO func ptr
    }
    else {
        qname_table_alloc(app_config.cmdline_args.qname_file, &app_config.qname_table);
        // TODO func ptr
    }

    // Check validity of port mask
    if (app_config.dpdk_config.enabled_port_mask & ~((1 << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
                 (1 << nb_ports) - 1);

    rx_lcore_id = 0;
    qconf = NULL;

    // Initialize the port/queue configuration of each logical core
    RTE_ETH_FOREACH_DEV(portid) {
        // skip ports that are not enabled
        if ((app_config.dpdk_config.enabled_port_mask & (1 << portid)) == 0)
            continue;

        nb_ports_in_mask++;

        // get the lcore_id for this port
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               app_config.dpdk_config.lcore_queue_conf[rx_lcore_id].n_port ==
               app_config.dpdk_config.rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
        }

        if (qconf != &app_config.dpdk_config.lcore_queue_conf[rx_lcore_id]) {
            // Assigned a new logical core in the loop above
            qconf = &app_config.dpdk_config.lcore_queue_conf[rx_lcore_id];
            nb_lcores++;
        }

        qconf->port_list[qconf->n_port] = portid;
        qconf->n_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
    }

    // Initialise each port
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = app_config.dpdk_config.port_conf;
        struct rte_eth_dev_info dev_info;

        if ((app_config.dpdk_config.enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", portid);
            continue;
        }
        nb_ports_available++;

        printf("Initializing port %u... ", portid);
        fflush(stdout);
        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
                    DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                     ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &app_config.dpdk_config.nb_rxd,
                                               &app_config.dpdk_config.nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot adjust number of descriptors: err=%d, port=%u\n",
                     ret, portid);

        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, 0, app_config.dpdk_config.nb_rxd,
                                     rte_eth_dev_socket_id(portid),
                                     &rxq_conf,
                                     app_config.dpdk_config.pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                     ret, portid);

        // init one TX queue on each port
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, app_config.dpdk_config.nb_txd,
                                     rte_eth_dev_socket_id(portid),
                                     &txq_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                     ret, portid);

        // Initialize TX buffers
        app_config.dpdk_config.tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                                               RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                               rte_eth_dev_socket_id(portid));
        if (app_config.dpdk_config.tx_buffer[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                     portid);

        rte_eth_tx_buffer_init(app_config.dpdk_config.tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_tx_buffer_set_err_callback(app_config.dpdk_config.tx_buffer[portid],
                                                 rte_eth_tx_buffer_count_callback,
                                                 &app_config.port_stats[portid].tx_dropped);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot set error callback for tx buffer on port %u\n",
                     portid);

        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                     ret, portid);

        printf("done: \n");

        rte_eth_promiscuous_enable(portid);

        // initialize port stats
        memset(&app_config.port_stats[portid], 0, sizeof(struct port_stats));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
                 "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(app_config.dpdk_config.enabled_port_mask);

    ret = 0;
    // launch per-lcore init on every lcore
    rte_eal_mp_remote_launch(tcpgen_launch_one_lcore, &app_config, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    RTE_ETH_FOREACH_DEV(portid) {
        if ((app_config.dpdk_config.enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }

    qname_table_free(&app_config.qname_table);
    pcap_list_destroy(&app_config.pcap_list);

    printf("Bye...\n");

    return ret;
}