#include <rte_ethdev.h>
#include <rte_cycles.h>
#include "rte_ikcp.h"

#define RTE_LOGTYPE_IKCP         RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_IKCP_PRIVATE RTE_LOGTYPE_USER1

#define IKCP_INPUT_BUF_MAX_SIZE (1 << 16)

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

	return (int32_t)rte_eth_tx_burst(port_id, txq_id, &head, 1);
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

struct rte_ikcp * rte_ikcp_create(struct rte_ikcp_config config, uint32_t conv, void *user)
{
	struct rte_eth_dev *dev;
	struct rte_ikcp *ikcp;
	uint16_t port_id;
	uint16_t txq_id;

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

	if (ikcp->config.flags & RTE_IKCP_ENABLE_PRIVATE_LOG) {
		ikcp->kcp.logmask = ~0;
		ikcp->kcp.writelog = rte_ikcp_log;
		RTE_LOG(ERR, IKCP, "enable log\n");
	}

	ikcp->config = config;
	ikcp->config.flags |= RTE_IKCP_USED;
	if (ikcp->config.flags & RTE_IKCP_ENABLE_PRIVATE_LOG) {
		ikcp->kcp.logmask = ~0;
		ikcp->kcp.writelog = rte_ikcp_log;
	}

	ikcp_setoutput(&ikcp->kcp, ikcp_output);

	/* TODO: Set mss smaller than MTU. */

	return ikcp;
}

int32_t rte_ikcp_update(struct rte_ikcp *ikcp)
{
	ikcp_update(&ikcp->kcp, rte_rdtsc() / rte_get_tsc_hz() * 100);

	return 0;
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

	RTE_LOG(DEBUG, IKCP, "ikcp input: %s(%u).\n", data, len);

	return ikcp_input(&ikcp->kcp, data, len);
}