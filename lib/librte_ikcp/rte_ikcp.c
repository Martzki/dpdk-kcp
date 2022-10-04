#include <rte_ethdev.h>
#include <rte_cycles.h>
#include "rte_ikcp.h"

#define RTE_LOGTYPE_IKCP         RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_IKCP_PRIVATE RTE_LOGTYPE_USER1

#define IKCP_INPUT_BUF_MAX_SIZE (1 << 16)
#define IKCP_INPUT_BURST_SIZE 32U

#define IKCP_MQ_NAME_SZIE 64
#define IKCP_TX_QUEUE_NAME_FMT "IKCP_TX_%u_%u"
#define IKCP_RX_QUEUE_NAME_FMT "IKCP_RX_%u_%u"
#define IKCP_TX_QUEUE_SIZE 4096
#define IKCP_RX_QUEUE_SIZE 4096

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

struct rte_ikcp ikcp_list[RTE_MAX_ETHPORTS][MAX_IKCP_PER_PORT];

static inline int32_t ikcp_is_ipv4(struct rte_ikcp *ikcp)
{
	return ikcp->config.flags & RTE_IKCP_L3_TYPE_IPV4;
}

static inline void rte_ikcp_log(const char *log, struct IKCPCB *kcp, void *user)
{
	RTE_LOG(DEBUG, IKCP_PRIVATE, "kcp[%p]: %s\n", kcp, log);
	RTE_SET_USED(user);
}

static inline int32_t ikcp_output(const char *buf, int32_t len, ikcpcb *kcp, void *user)
{
	struct rte_ikcp *ikcp;
	struct rte_mempool *mempool;
	struct rte_mbuf *head, *mbuf;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint16_t port_id;
	uint16_t txq_id;
	uint16_t buf_size;
	uint16_t nb_segs;
	uint16_t i;
	uint16_t offset;
	uint16_t is_ipv4;
	uint16_t hdr_len;
	uint16_t copy_len;
	int32_t nb_tx;

	ikcp = container_of(kcp, struct rte_ikcp, kcp);
	port_id = ikcp->config.port_id;
	txq_id = ikcp->config.txq_id;
	mempool = ikcp->config.mempool;
	is_ipv4 = ikcp_is_ipv4(ikcp);
	buf_size = rte_pktmbuf_data_room_size(mempool) - RTE_PKTMBUF_HEADROOM;

	head = mbuf = rte_pktmbuf_alloc(mempool);
	if (unlikely(!mbuf)) {
		RTE_LOG(ERR, IKCP, "Alloc mbuf failed.\n");
		return 0;
	}

	/* Fill L2 info. */
	ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	memset(ether_hdr, 0, sizeof(struct rte_ether_hdr));
	rte_ether_addr_copy(&ikcp->config.next_hop_mac, &ether_hdr->d_addr);
	rte_eth_macaddr_get(port_id, &ether_hdr->s_addr);
	mbuf->l2_len = sizeof(struct rte_ether_hdr);

	/* Fill L3 info. */
	if (is_ipv4) {
		ether_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
		ipv4_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
		memset(ipv4_hdr, 0, sizeof(struct rte_ipv4_hdr));
		ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
		ipv4_hdr->type_of_service = 0;
		ipv4_hdr->fragment_offset = 0;
		ipv4_hdr->time_to_live = 64;
		ipv4_hdr->next_proto_id	= IPPROTO_UDP;
		ipv4_hdr->packet_id = 0;
		ipv4_hdr->src_addr = htonl(ikcp->config.src_ip.ipv4);
		ipv4_hdr->dst_addr = htonl(ikcp->config.dst_ip.ipv4);
		ipv4_hdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + len);
		mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
	}
	else {
		ether_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);
		/* TODO: ipv6 */
	}

	/* Fill L4 info. */
	udp_hdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(mbuf, char *) + mbuf->l2_len + mbuf->l3_len);
	memset(udp_hdr, 0, sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = htons(ikcp->config.src_port);
	udp_hdr->dst_port = htons(ikcp->config.dst_port);
	udp_hdr->dgram_len = htons(sizeof(struct rte_udp_hdr) + len);
	mbuf->l4_len = sizeof(struct rte_udp_hdr);

	/* Fill payload. */
	hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
	copy_len = RTE_MIN(buf_size - hdr_len, len);
	rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, void *, mbuf->l2_len + mbuf->l3_len + mbuf->l4_len), buf, copy_len);
	offset = copy_len;

	/* Do checksum. */
	if (is_ipv4) {
		udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	}
	else {
		/* TODO */
	}

	/* Fill mbuf info. */
	mbuf->nb_segs = 1;
	mbuf->pkt_len = hdr_len + len;
	mbuf->ol_flags = 0;
	mbuf->vlan_tci = 0;
	mbuf->vlan_tci_outer = 0;
	mbuf->data_len = hdr_len + copy_len;

	/* Chain segments. */
	if (unlikely(len > copy_len)) {
		nb_segs = DIV_ROUND_UP(len - copy_len, buf_size);
		for (i = 0; i < nb_segs; i++) {
			mbuf->next = rte_pktmbuf_alloc(mempool);
			if (unlikely(!mbuf->next)) {
				RTE_LOG(ERR, IKCP, "Alloc mbuf failed.\n");
				rte_pktmbuf_free(head);
				return 0;
			}

			copy_len = RTE_MIN(buf_size, len - offset);
			rte_memcpy(rte_pktmbuf_mtod(mbuf->next, void *), buf + offset, copy_len);
			mbuf = mbuf->next;
			offset += copy_len;
			mbuf->data_len = copy_len;
		}
		head->nb_segs += nb_segs;
	}

	mbuf->next = NULL;

	RTE_SET_USED(user);

	if (ikcp->config.flags & RTE_IKCP_MQ) {
		nb_tx = (int32_t)rte_ring_sp_enqueue(ikcp->tx_queue, head) ? 0 : 1;
	}
	else {
		nb_tx = (int32_t)rte_eth_tx_burst(port_id, txq_id, &head, 1);
		rte_pktmbuf_free(head);
	}

	return nb_tx;
}

static inline struct rte_ikcp * find_next_valid_ikcp(uint16_t port_id, uint32_t conv)
{
	int32_t i;

	for (i = 0; i < MAX_IKCP_PER_PORT; ++i) {
			if (!(ikcp_list[port_id][i].config.flags & RTE_IKCP_USED) ||
				(ikcp_list[port_id][i].kcp.conv == conv)) {
				return &ikcp_list[port_id][i];
			}
	}

	return NULL;
}

static inline int ikcp_release_cb(uint16_t port_id __rte_unused,
				enum rte_eth_event_type event,
				void *cb_arg, void *out __rte_unused)
{
	if (event != RTE_ETH_EVENT_DESTROY)
		return 0;

	rte_ikcp_release(cb_arg);

	return 0;
}

struct rte_ikcp * rte_ikcp_create(struct rte_ikcp_config config, uint32_t conv, void *user)
{
	struct rte_eth_dev *dev;
	struct rte_ikcp *ikcp;
	char queue_name[IKCP_MQ_NAME_SZIE];
	uint16_t port_id, txq_id, mtu;

	port_id = config.port_id;
	txq_id = config.txq_id;

	if (unlikely(!rte_eth_dev_is_valid_port(port_id))) {
		RTE_LOG(ERR, IKCP, "Port: %hu is invalid.\n", port_id);
		return NULL;
	}

	dev = &rte_eth_devices[port_id];

	if (unlikely(txq_id > dev->data->nb_tx_queues)) {
		RTE_LOG(ERR, IKCP, "Port: %hu has %hu tx queues "
				"but %hu required to set.\n",
				port_id, dev->data->nb_tx_queues, txq_id);
		return NULL;
	}

	ikcp = find_next_valid_ikcp(port_id, conv);
	if (unlikely(!ikcp)) {
		RTE_LOG(ERR, IKCP, "Can't get ikcp for port: %hu, conv: %u.\n", port_id, conv);
		return NULL;
	}

	/* kcp is already created. */
	if (ikcp->config.flags & RTE_IKCP_USED) {
		return ikcp;
	}

	/* Init kcp private data. */
	if (ikcp_init(&ikcp->kcp, conv, user)) {
		RTE_LOG(ERR, IKCP, "Init ikcp for port: %hu failed.\n", port_id);
		return NULL;
	}

	ikcp->config = config;
	if (ikcp->config.flags & RTE_IKCP_ENABLE_PRIVATE_LOG) {
		ikcp->kcp.logmask = ~0;
		ikcp->kcp.writelog = rte_ikcp_log;
	}

	if (ikcp->config.flags & RTE_IKCP_MQ) {
		snprintf(queue_name, IKCP_MQ_NAME_SZIE, IKCP_RX_QUEUE_NAME_FMT, port_id, conv);
		ikcp->rx_queue = rte_ring_create(queue_name, IKCP_RX_QUEUE_SIZE, SOCKET_ID_ANY, RING_F_SC_DEQ);
		if (!ikcp->rx_queue) {
			RTE_LOG(ERR, IKCP, "Create rx queue for port: %u conv: %u failed.\n", port_id, conv);
			return NULL;
		}

		snprintf(queue_name, IKCP_MQ_NAME_SZIE, IKCP_TX_QUEUE_NAME_FMT, port_id, conv);
		ikcp->tx_queue = rte_ring_create(queue_name, IKCP_TX_QUEUE_SIZE, SOCKET_ID_ANY, RING_F_SP_ENQ);
		if (!ikcp->tx_queue) {
			RTE_LOG(ERR, IKCP, "Create tx queue for port: %u conv: %u failed.\n", port_id, conv);
			return NULL;
		}
	}

	ikcp_setoutput(&ikcp->kcp, ikcp_output);
	ikcp_nodelay(&ikcp->kcp, 1, 10, 2, 1);

	RTE_SET_USED(rte_eth_dev_get_mtu(port_id, &mtu));
	RTE_SET_USED(ikcp_setmtu(&ikcp->kcp, mtu));

	if (rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_DESTROY, ikcp_release_cb, &ikcp)) {
		RTE_LOG(ERR, IKCP, "Register callback for port: %u conv: %u failed.\n", port_id, conv);
		return NULL;
	}

	ikcp->config.flags |= RTE_IKCP_USED;

	return ikcp;
}

void rte_ikcp_release(struct rte_ikcp *ikcp)
{
	if (!(ikcp->config.flags))
		return;

	ikcp->config.flags = 0;
	rte_ring_free(ikcp->tx_queue);
	rte_ring_free(ikcp->rx_queue);
	ikcp_reset(&ikcp->kcp);
	rte_eth_dev_callback_unregister(ikcp->config.port_id, RTE_ETH_EVENT_DESTROY, ikcp_release_cb, ikcp);
}

uint64_t rte_ikcp_check(struct rte_ikcp *ikcp)
{
	uint32_t current;

	current = (uint32_t)((double)rte_rdtsc() / rte_get_tsc_hz() * 1000);
	return (uint64_t)(ikcp_check(&ikcp->kcp, current) / 1000 * rte_get_tsc_hz());
}

void rte_ikcp_update(struct rte_ikcp *ikcp)
{
	ikcp_update(&ikcp->kcp, (uint32_t)((double)rte_rdtsc() / rte_get_tsc_hz() * 1000));
}

int32_t rte_ikcp_send(struct rte_ikcp *ikcp, const char* data, int32_t len)
{
	return ikcp_send(&ikcp->kcp, data, len);
}

int32_t rte_ikcp_recv(struct rte_ikcp *ikcp, char* data, int32_t len)
{
	return ikcp_recv(&ikcp->kcp, data, len);
}

int32_t rte_ikcp_input(struct rte_ikcp *ikcp, struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	static char data[IKCP_INPUT_BUF_MAX_SIZE];
	int32_t len = 0;
	uint16_t is_ipv4, offset;

	is_ipv4 = ikcp_is_ipv4(ikcp);
	ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	if (is_ipv4) {
		if (ether_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV4) ||
			!rte_is_same_ether_addr(&ether_hdr->d_addr, &ikcp->config.self_mac)) {
			return -1;
		}

		ipv4_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
		if (ipv4_hdr->next_proto_id != IPPROTO_UDP ||
			ipv4_hdr->src_addr != htonl(ikcp->config.dst_ip.ipv4) ||
			ipv4_hdr->dst_addr != htonl(ikcp->config.src_ip.ipv4)) {
			return -1;
		}

		udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
		if (udp_hdr->src_port != htons(ikcp->config.dst_port) ||
			udp_hdr->dst_port != htons(ikcp->config.src_port)) {
			return -1;
		}

		offset = sizeof(struct rte_ipv4_hdr) +
				 sizeof(struct rte_ether_hdr) +
				 sizeof(struct rte_udp_hdr);
		if (unlikely(mbuf->pkt_len - offset > IKCP_INPUT_BUF_MAX_SIZE)) {
			return -1;
		}

		while (mbuf) {
			rte_memcpy(data, rte_pktmbuf_mtod_offset(mbuf, void *, offset), mbuf->data_len - offset);
			offset = 0;
			len += mbuf->data_len - offset;
			mbuf = mbuf->next;
		}
	}
	else {
		if (ether_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV6)) {
			return -1;
		}
	}

	// RTE_LOG(DEBUG, IKCP, "ikcp input: %s(%u).\n", data, len);

	ikcp_input(&ikcp->kcp, data, len);

	rte_pktmbuf_free(mbuf);

	return 0;
}

int32_t rte_ikcp_input_bulk(struct rte_ikcp *ikcp) {
	int nb_rx, i, count;
	struct rte_mbuf *mbufs[IKCP_INPUT_BURST_SIZE];

	if (!(ikcp->config.flags & RTE_IKCP_MQ)) {
		RTE_LOG(DEBUG, IKCP, "Multi queue is not enabled.\n");
		return -1;
	}

	count = RTE_MIN(rte_ring_count(ikcp->rx_queue), IKCP_INPUT_BURST_SIZE);
	if (!count) {
		return 0;
	}

	nb_rx = rte_ring_sc_dequeue_bulk(ikcp->rx_queue, (void **)mbufs, count, NULL);
	if (!nb_rx) {
		return 0;
	}

	for (i = 0; i < nb_rx; ++i) {
		rte_ikcp_input(ikcp, mbufs[i]);
	}

	return 0;
}

void rte_ikcp_flush(struct rte_ikcp *ikcp)
{
	ikcp_flush(&ikcp->kcp);
}

void rte_ikcp_nodelay(struct rte_ikcp *ikcp, int32_t nodelay,
					  int32_t interval, int32_t resend, int32_t nc)
{
	RTE_SET_USED(ikcp_nodelay(&ikcp->kcp, nodelay, interval, resend, nc));
}

int32_t rte_ikcp_peeksize(struct rte_ikcp *ikcp)
{
	return ikcp_peeksize(&ikcp->kcp);
}

int32_t rte_ikcp_setmtu(struct rte_ikcp *ikcp, int32_t mtu)
{
	return ikcp_setmtu(&ikcp->kcp, mtu);
}

int32_t rte_ikcp_wndsize(struct rte_ikcp *ikcp, int32_t sndwnd, int32_t rcvwnd)
{
	return ikcp_wndsize(&ikcp->kcp, sndwnd, rcvwnd);
}

int32_t rte_ikcp_waitsnd(struct rte_ikcp *ikcp)
{
	return ikcp_waitsnd(&ikcp->kcp);
}