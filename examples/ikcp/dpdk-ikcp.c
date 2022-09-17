#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ikcp.h>

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define MAX_LONG_OPT_SZ 64
#define MEMPOOL_SIZE 8192
#define MEMPOOL_CACHE_SIZE 256
#define BURST_SIZE 32
#define SEND_NUM 1
#define PAYLOAD_LEN 128
#define UDP_SRC_PORT 6655
#define UDP_DST_PORT 6655
#define DEV_NAME_LEN 128
#define IKCP_CONV 6655
#define CMD_SIZE 64
#define SEND_CMD "send"
#define STOP_CMD "stop"
#define EXIT_CMD "exit"
#define SEND_STATUS 1
#define STOP_STATUS 0
#define LOOP_RUNNING 1
#define LOOP_STOP 0

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

struct rte_mempool *g_pktmbuf_pool = NULL;
void *g_ikcp;
int g_sock;
struct sockaddr_in g_src,g_dst;
static char g_device_name[DEV_NAME_LEN];
static struct rte_ether_addr g_dst_mac;
static uint16_t g_portid;
static uint32_t g_src_ip, g_dst_ip;
static int g_send_status;
static int g_loop;
static int g_is_ipv4 = 1;
static int g_dpdk_kcp_debug;
static int g_dpdk_kcp_mq = 0;
static uint16_t g_dpdk_kcp_lcore = RTE_MAX_LCORE;

int parse_args(int argc, char **argv, int is_pmd);
int dpdk_slave_loop(__rte_unused void *arg);
int master_loop(void);
int send_mbuf(struct rte_mbuf **mbufs, uint64_t pkt_idx);
int socket_ikcp_output(const char *buf, int len, __rte_unused ikcpcb *kcp, __rte_unused void *user);
void *socket_slave_loop(__rte_unused void *arg);
uint32_t get_timestamp(void);

int parse_args(int argc, char **argv, int is_pmd)
{
	int opt, option_index;
	static struct option dpdk_long_option[] = {
		{"device", required_argument, NULL, 0},
		{"src", required_argument, NULL, 0},
		{"dst", required_argument, NULL, 0},
		{"next-hop-mac", required_argument, NULL, 0},
		{"multi-queue", no_argument, &g_dpdk_kcp_mq, 1},
		{"debug", no_argument, &g_dpdk_kcp_debug, 1},
		{NULL, 0, 0, 0},
	};

	static struct option socket_long_option[] = {
		{"src", required_argument, NULL, 0},
		{"dst", required_argument, NULL, 0},
		{NULL, 0, 0, 0},
	};

	if (is_pmd) {
		while ((opt = getopt_long(argc, argv, "46h",
				dpdk_long_option, &option_index)) != EOF) {
			switch(opt) {
			case '4':
				g_is_ipv4 = 1;
				printf("ipv4\n");
				break;
			case '6':
				g_is_ipv4 = 0;
				printf("ipv6\n");
				break;
			case 0:
				if (!strncmp(dpdk_long_option[option_index].name, "device", MAX_LONG_OPT_SZ)) {
					snprintf(g_device_name, DEV_NAME_LEN, "%s", optarg);
				}
				if (!strncmp(dpdk_long_option[option_index].name, "src", MAX_LONG_OPT_SZ)) {
					struct in_addr addr;
					if (!inet_aton(optarg, &addr)) {
						RTE_LOG(CRIT, APP, "Invalid argument: %s.\n", optarg);
						return -1;
					}
					g_src_ip = rte_be_to_cpu_32(addr.s_addr);
				}
				if (!strncmp(dpdk_long_option[option_index].name, "dst", MAX_LONG_OPT_SZ)) {
					struct in_addr addr;
					if (!inet_aton(optarg, &addr)) {
						RTE_LOG(CRIT, APP, "Invalid argument: %s.\n", optarg);
						return -1;
					}
					g_dst_ip = rte_be_to_cpu_32(addr.s_addr);
				}
				if (!strncmp(dpdk_long_option[option_index].name, "next-hop-mac", MAX_LONG_OPT_SZ)) {
					if (rte_ether_unformat_addr(optarg, &g_dst_mac)) {
						RTE_LOG(CRIT, APP, "Invalid argument: %s.\n", optarg);
						return -1;
					}
				}
				if (!strncmp(dpdk_long_option[option_index].name, "multi-queue", MAX_LONG_OPT_SZ)) {
					g_dpdk_kcp_mq = 1;
				}
				if (!strncmp(dpdk_long_option[option_index].name, "debug", MAX_LONG_OPT_SZ)) {
					g_dpdk_kcp_debug = 1;
				}
				break;
			case 'h':
			default:
				printf("%s [EAL options] -- [--debug] [-4|-6] --device PCI --src SRC"
				" --dst DST --next-hop-mac M:M:M:M:M:M\n"
				"		-4: Use IPv4 (default)\n"
				"		-6: Use IPv6\n"
				"		--device: Assign the PCI address of device\n"
				"		--src: Assign the source IP\n"
				"		--dst: Assign the destination IP\n"
				"		--next-hop-mac: Assign the MAC address of the next hop\n"
				"		--multi-queue: Use multi queues to transmit\n"
				"		--debug: Enable kcp private log\n",
				       argv[0]);
				return -1;
			}
		}
		if (*g_device_name == 0) {
			printf("--device is required\n");
			return -1;
		}
		if (!g_src_ip) {
			printf("--src is required\n");
			return -1;
		}
		if (!g_dst_ip) {
			printf("--dst is required\n");
			return -1;
		}
		if (rte_is_zero_ether_addr(&g_dst_mac)) {
			printf("--next-hop-mac is required\n");
			return -1;
		}
	}
	else {
		while ((opt = getopt_long(argc, argv, "46h",
				socket_long_option, &option_index)) != EOF) {
			switch(opt) {
			case '4':
				g_is_ipv4 = 1;
				break;
			case '6':
				g_is_ipv4 = 0;
				break;
			case 0:
				if (!strncmp(socket_long_option[option_index].name, "src", MAX_LONG_OPT_SZ)) {
					g_src.sin_family = AF_INET;
					g_src.sin_port = htons(UDP_SRC_PORT);
					if (!inet_aton(optarg, &g_src.sin_addr)) {
						printf("Invalid argument: %s.\n", optarg);
						return -1;
					}
				}
				if (!strncmp(socket_long_option[option_index].name, "dst", MAX_LONG_OPT_SZ)) {
					g_dst.sin_family = AF_INET;
					g_dst.sin_port = htons(UDP_DST_PORT);
					if (!inet_aton(optarg, &g_dst.sin_addr)) {
						printf("Invalid argument: %s.\n", optarg);
						return -1;
					}
				}
				break;
			case 'h':
			default:
				printf("%s [-4|-6] --dst DST\n"
				"		-4: IP address is IPv4 (default)\n"
				"		-6: IP address is IPv6\n"
				"		--dst: Assign the destination IP\n",
				       argv[0]);
				return -1;
			}
		}
		if (!g_dst.sin_addr.s_addr) {
			printf("--dst is required\n");
			return -1;
		}
	}

	return 0;
}

int dpdk_slave_loop(__rte_unused void *arg)
{
	struct rte_ikcp *ikcp = (struct rte_ikcp *)g_ikcp;
	struct rte_mbuf *mbufs[BURST_SIZE];
	struct rte_eth_dev *dev;
	uint16_t work_id, txq_idx, rxq_idx, nb_rx;
	uint64_t pkt_idx, ikcp_interval, send_interval, ikcp_tsc = 0, send_tsc = 0, tsc;
	char buf[PAYLOAD_LEN] = {0}, out_buf[PAYLOAD_LEN] = {0};
	int32_t recv_len;
	int i, enable_send = 0, enable_recv = 0;

	if (!g_dpdk_kcp_mq && g_dpdk_kcp_lcore != rte_lcore_id()) {
		RTE_LOG(INFO, APP, "lcore: %u exit.\n", rte_lcore_id());
		return 0;
	}

	work_id = rte_lcore_id() % rte_lcore_count() + 1;
	dev = &rte_eth_devices[g_portid];
	rxq_idx = dev->data->nb_rx_queues % work_id;
	txq_idx = dev->data->nb_tx_queues % work_id;
	enable_send = work_id > dev->data->nb_rx_queues ? 0 : 1;
	enable_recv = work_id > dev->data->nb_rx_queues ? 0 : 1;
	pkt_idx = 0;

	if (unlikely(!enable_send && !enable_recv)) {
		RTE_LOG(INFO, APP, "Both send and recv are disabled in lcore: %u.\n", rte_lcore_id());
		return 0;
	}

	RTE_LOG(INFO, APP, "lcore: %u enable_send: %d txq_idx: %u enable_recv: %d rxq_idx: %u\n",
			rte_lcore_id(), enable_send, txq_idx, enable_recv, rxq_idx);

	/* Around 10 ms. */
	ikcp_interval = rte_get_tsc_hz() / 100;

	/* Around 500ms. */
	send_interval = rte_get_tsc_hz() / 2 / 50;

	RTE_LOG(INFO, APP, "tsc hz: %"PRIu64" ikcp_interval: %"PRIu64" send_interval: %"PRIu64"\n",
			rte_get_tsc_hz(), ikcp_interval, send_interval);

	while (g_loop) {
		if (g_dpdk_kcp_lcore == rte_lcore_id()) {
			tsc = rte_rdtsc();
			/* Update ikcp. */
			if (tsc - ikcp_tsc > ikcp_interval) {
				ikcp_interval = tsc;
				rte_ikcp_update(ikcp);
			}

			/* ikcp recv. */
			recv_len = rte_ikcp_recv(ikcp, buf, PAYLOAD_LEN);
			if (recv_len > 0) {
				strncpy(out_buf, buf, recv_len);
				RTE_LOG(INFO, APP, "ikcp recv: %s.\n", out_buf);
			}

			/* ikcp send. */
			if (tsc - send_tsc > send_interval && g_send_status == SEND_STATUS) {
				send_tsc = tsc;
				snprintf(buf, PAYLOAD_LEN, "[%u] Pkt No.%" PRIu64, rte_lcore_id(), pkt_idx++);
				if (rte_ikcp_send(ikcp, buf, strlen(buf)) < 0) {
					RTE_LOG(ERR, APP, "ikcp send failed.\n");
				}
			}

			if (g_dpdk_kcp_mq) {
				if (unlikely(rte_ikcp_input_bulk(ikcp) < 0)) {
					RTE_LOG(DEBUG, APP, "ikcp input failed.\n");
				}
			}
		}

		/* Recv pkts. */
		if (enable_recv) {
			nb_rx = rte_eth_rx_burst(g_portid, rxq_idx, mbufs, BURST_SIZE);
			if (!nb_rx) {
				goto send_pkts;
			}

			if (g_dpdk_kcp_mq) {
				if (!rte_ring_mp_enqueue_bulk(ikcp->rx_queue, (void **)mbufs, nb_rx, NULL)) {
					rte_pktmbuf_free_bulk(mbufs, nb_rx);
				}
			}
			else {
				for (i = 0; i < nb_rx; i++) {
					if (unlikely(rte_ikcp_input(ikcp, mbufs[i]))) {
						RTE_LOG(DEBUG, APP, "ikcp input failed.\n");
					}
				}
			}
		}

send_pkts:
		/* Send pkts. */
		if (enable_send && g_dpdk_kcp_mq) {
			if (!rte_ring_mc_dequeue(ikcp->tx_queue, (void **)mbufs)) {
				rte_eth_tx_burst(g_portid, txq_idx, mbufs, 1);
				rte_pktmbuf_free(mbufs[0]);
			}
		}
	}

	return 0;
}

int master_loop(void)
{
	char cmd[CMD_SIZE];

	while (1) {
		printf("cli > ");
		fgets(cmd, CMD_SIZE, stdin);
		cmd[strlen(cmd) - 1] = 0;
		if (!strcmp(cmd, SEND_CMD)) {
			g_send_status = SEND_STATUS;
		}
		else if (!strcmp(cmd, STOP_CMD)){
			g_send_status = STOP_STATUS;
		}
		else if (!strcmp(cmd, EXIT_CMD)) {
			g_loop = 0;
			break;
		}
		else {
			printf("cli > support commands: %s %s %s\n", SEND_CMD, STOP_CMD, EXIT_CMD);
		}
	}

	return 0;
}

int send_mbuf(struct rte_mbuf **mbufs, uint64_t pkt_idx)
{
	struct rte_mbuf *mbuf;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	char *payload;
	int pkt_len;
	uint16_t nb_tx;

	pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + PAYLOAD_LEN;
	mbuf = rte_pktmbuf_alloc(g_pktmbuf_pool);
	if (!mbuf) {
		RTE_LOG(ERR, APP, "Alloc mbuf failed\n");
		return -1;
	}

	nb_tx = 1;

	mbuf->data_len = pkt_len;
	mbuf->next = NULL;

	/* Fill L2 info. */
	ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(&g_dst_mac, &ether_hdr->d_addr);
	rte_eth_macaddr_get(g_portid, &ether_hdr->s_addr);
	ether_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	/* Fill L3 info. */
	ipv4_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
	memset(ipv4_hdr, 0, sizeof(struct rte_ipv4_hdr));
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = 64;
	ipv4_hdr->next_proto_id	= IPPROTO_UDP;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->src_addr = htonl(g_src_ip);
	ipv4_hdr->dst_addr = htonl(g_dst_ip);
	ipv4_hdr->total_length = htons(pkt_len - sizeof(struct rte_ether_hdr));
	ipv4_hdr->hdr_checksum = 0;

	/* Fill L4 info. */
	udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
	udp_hdr->src_port = htons(UDP_SRC_PORT);
	udp_hdr->dst_port = htons(UDP_DST_PORT);
	udp_hdr->dgram_cksum = 0;
	udp_hdr->dgram_len = htons(pkt_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

	/* Fill payload. */
	payload = (char *)(udp_hdr + 1);
	memset(payload, 0, PAYLOAD_LEN);
	snprintf(payload, PAYLOAD_LEN, "Pkt No.%" PRIu64, pkt_idx);

	/* Do checksum. */
	udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

	/* Fill mbuf info. */
	mbuf->nb_segs = 1;
	mbuf->pkt_len = pkt_len;
	mbuf->ol_flags = 0;
	mbuf->vlan_tci = 0;
	mbuf->vlan_tci_outer = 0;
	mbuf->l2_len = sizeof(struct rte_ether_hdr);
	mbuf->l3_len = sizeof(struct rte_ipv4_hdr);

	mbufs[0] = mbuf;

	return nb_tx;
}

uint32_t get_timestamp(void)
{
	struct timeval time;

	gettimeofday(&time, NULL);

	return (uint32_t)(time.tv_sec * 1000 + time.tv_usec / 1000);
}

int socket_ikcp_output(const char *buf, int len, __rte_unused ikcpcb *kcp, __rte_unused void *user)
{
	if (sendto(g_sock, buf, len, 0, (struct sockaddr *)&g_dst, sizeof(g_dst)) <= 0) {
		perror("sendto failed");
		return -1;
	}

	return 0;
}

void *socket_slave_loop(__rte_unused void *arg)
{
	static char suffix[] = " ACK";
	char buf[PAYLOAD_LEN + 1];
	uint64_t ts, last_ts = 0;
	socklen_t len;
	ssize_t recv_len;
	ikcpcb *ikcp = (ikcpcb *)g_ikcp;

	while (g_loop) {
		ts = get_timestamp();
		if (ts - last_ts > 20) {
			ikcp_update(ikcp, ts);
			last_ts = ts;
		}

		recv_len = recvfrom(g_sock, buf, PAYLOAD_LEN, 0, (struct sockaddr *)&g_dst, &len);
		if (recv_len <= 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("Recv failed");
			}
			continue;
		}

		// printf("udp recv: %s(%zu) dst: %d\n", buf, recv_len, g_dst.sin_addr.s_addr);

		ikcp_input(ikcp, buf, recv_len);

		recv_len = ikcp_recv(ikcp, buf, PAYLOAD_LEN);
		if (recv_len <= 0) {
			continue;
		}

		buf[recv_len] = 0;
		printf("ikcp recv: %s.\n", buf);
		strcpy(buf + recv_len, suffix);

		if (ikcp_send(ikcp, buf, recv_len + strlen(suffix)) < 0) {
			perror("ikcp send failed");
			continue;
		}
	}

	return NULL;
}

int main(int argc, char **argv)
{
	int ret = 0, is_pmd;
	char prog[64];

	if (argc > 1 && !strcmp(argv[1], "--socket-kcp")) {
		is_pmd = 0;
		snprintf(prog, 64, "%s --socket-kcp", argv[0]);
	}
	else if (argc > 1 && !strcmp(argv[1], "--dpdk-kcp")) {
		is_pmd = 1;
		snprintf(prog, 64, "%s --dpdk-kcp", argv[0]);
	}
	else {
		printf("Usage: %s [options]\n"
			   "options:\n"
			   "  --socket-kcp: Use kcp socket backend\n"
			   "  --dpdk-kcp: Use kcp pmd backend\n", argv[0]);
		exit(-1);
	}

	--argc;
	++argv;
	argv[0] = prog;

	/* pmd mode. */
	if (is_pmd) {
		int i, nb_rx_q, nb_tx_q;
		uint16_t lcoreid;
		struct rte_eth_dev *dev;
		struct rte_eth_dev_info dev_info;
		struct rte_ikcp_config ikcp_config;

		ret = rte_eal_init(argc, argv);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Can't init eal.\n");
		}

		argc -= ret;
		argv += ret;

		if (parse_args(argc, argv, is_pmd)) {
			rte_eal_cleanup();
			exit(-1);
		}

		RTE_ETH_FOREACH_DEV(g_portid) {
			dev = &rte_eth_devices[g_portid];
			if (!strcmp(dev->device->name, g_device_name)) {
				break;
			}
			dev = NULL;
		}

		if (!dev) {
			rte_exit(EXIT_FAILURE, "Device %s is not a valid port.\n", g_device_name);
		}

		g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", MEMPOOL_SIZE,
			MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
		if (!g_pktmbuf_pool) {
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
		}

		RTE_LOG(INFO, APP, "lcore count: %u\n", rte_lcore_count());

		RTE_LCORE_FOREACH_SLAVE(lcoreid) {
			RTE_LOG(INFO, APP, "lcore%u is enabled.\n", lcoreid);
		}

		ret = rte_eth_dev_info_get(g_portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				g_portid, strerror(-ret));

		/* Multi-queue enable. */
		if (g_dpdk_kcp_mq) {
			nb_rx_q = RTE_MIN(dev_info.max_rx_queues, rte_lcore_count());
			nb_tx_q = RTE_MIN(dev_info.max_tx_queues, rte_lcore_count());
		}
		else {
			nb_rx_q = nb_tx_q = 1;
		}

		RTE_LOG(INFO, APP, "lcore num: %u, nb_rx_q: %u, nb_tx_q: %u.\n", rte_lcore_count(), nb_rx_q, nb_tx_q);

		ret = rte_eth_dev_configure(g_portid, nb_rx_q, nb_tx_q, &port_conf_default);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					ret, g_portid);

		/* Setup rx queues. */
		for (i = 0; i < nb_rx_q; i++) {
			ret = rte_eth_rx_queue_setup(g_portid, i, 0,
					rte_eth_dev_socket_id(g_portid), &dev_info.default_rxconf, g_pktmbuf_pool);
			if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					ret, g_portid);
		}

		/* Setup tx queues. */
		for (i = 0; i < nb_tx_q; i++) {
			ret = rte_eth_tx_queue_setup(g_portid, i, 0,
					rte_eth_dev_socket_id(g_portid), &dev_info.default_txconf);
			if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
					ret, g_portid);
		}

		/* Start the device. */
		ret = rte_eth_dev_start(g_portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
					ret, g_portid);

		g_dpdk_kcp_lcore = rte_get_next_lcore(-1, 1, 0);
		if (g_dpdk_kcp_lcore == RTE_MAX_LCORE) {
			rte_exit(EXIT_FAILURE, "Can't get work lcore.\n");
		}

		ikcp_config.port_id = g_portid;
		ikcp_config.txq_id = 0;
		ikcp_config.src_ip.ipv4 = g_src_ip;
		ikcp_config.dst_ip.ipv4 = g_dst_ip;
		ikcp_config.src_port = UDP_SRC_PORT;
		ikcp_config.dst_port = UDP_DST_PORT;
		rte_eth_macaddr_get(ikcp_config.port_id, &ikcp_config.self_mac);
		rte_ether_addr_copy(&g_dst_mac, &ikcp_config.next_hop_mac);
		ikcp_config.mempool = g_pktmbuf_pool;
		ikcp_config.flags |= g_is_ipv4 ? RTE_IKCP_L3_TYPE_IPV4 : RTE_IKCP_L3_TYPE_IPV6;
		if (g_dpdk_kcp_mq) {
			ikcp_config.flags |= RTE_IKCP_MQ;
		}

		if (g_dpdk_kcp_debug) {
			ikcp_config.flags |= RTE_IKCP_ENABLE_PRIVATE_LOG;
		}

		g_ikcp = (void *)rte_ikcp_create(ikcp_config, IKCP_CONV, NULL);
		if (!g_ikcp) {
			rte_exit(EXIT_FAILURE, "Create ikcp for port: %hu failed.\n", g_portid);
		}

		g_loop = LOOP_RUNNING;
		g_send_status = SEND_STATUS;

		rte_eal_mp_remote_launch(dpdk_slave_loop, NULL, SKIP_MASTER);

		master_loop();

		RTE_LCORE_FOREACH_SLAVE(lcoreid) {
			if (rte_eal_wait_lcore(lcoreid) < 0) {
				ret = -1;
				break;
			}
		}

		RTE_LOG(INFO, APP, "Closing port %d...", g_portid);
		rte_eth_dev_stop(g_portid);
		rte_eth_dev_close(g_portid);
		RTE_LOG(INFO, APP, "Done\n");
	}
	/* linux socket mode. */
	else {
		pthread_t tid;

		if (parse_args(argc, argv, is_pmd)) {
			exit(-1);
		}

		g_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (g_sock < 0) {
			perror("Create socket failed");
			return -1;
		}

		g_src.sin_family = AF_INET;
		g_src.sin_port = htons(UDP_DST_PORT);
		g_src.sin_addr.s_addr = g_src.sin_addr.s_addr ? g_src.sin_addr.s_addr : htons(INADDR_ANY);

		if (bind(g_sock, (struct sockaddr *)&g_src, sizeof(g_src))) {
			perror("Bind failed");
			close(g_sock);
			return -1;
		}

		g_ikcp = (void *)ikcp_create(IKCP_CONV, NULL);
		if (!g_ikcp) {
			perror("Create ikcp failed");
			close(g_sock);
			return -1;
		}

		ikcp_setoutput(g_ikcp, socket_ikcp_output);
		ikcp_nodelay(g_ikcp, 1, 10, 2, 1);

		g_loop = LOOP_RUNNING;
		g_send_status = SEND_STATUS;

		if (pthread_create(&tid, NULL, socket_slave_loop, NULL)) {
			perror("Create thread failed");
			close(g_sock);
			return -1;
		}

		master_loop();

		pthread_join(tid, NULL);
	}

	return ret;
}