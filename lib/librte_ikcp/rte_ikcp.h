#ifndef _RTE_IKCP_H_
#define _RTE_IKCP_H_

#include <stdint.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_net.h>
#include "ikcp.h"

#define MAX_IKCP_PER_PORT 16

#define RTE_IKCP_USED               (1 << 0)
#define RTE_IKCP_L3_TYPE_IPV4       (1 << 1)
#define RTE_IKCP_L3_TYPE_IPV6       (1 << 2)
#define RTE_IKCP_ENABLE_PRIVATE_LOG (1 << 3)
#define RTE_IKCP_MQ                 (1 << 4)

#define RTE_IKCP_L3_TYPE_MASK (RTE_IKCP_L3_TYPE_IPV4 | RTE_IKCP_L3_TYPE_IPV6)

#ifdef __cplusplus
extern "C" {
#endif

struct rte_ikcp_config {
	uint16_t port_id;
	uint16_t txq_id;
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	} src_ip, dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	struct rte_ether_addr self_mac, next_hop_mac;
	struct rte_mempool *mempool;
	uint32_t flags;
};

struct rte_ikcp {
	ikcpcb kcp;
	struct rte_ikcp_config config;
	struct rte_ring *rx_queue, *tx_queue;
};

struct rte_ikcp *rte_ikcp_create(struct rte_ikcp_config config, uint32_t conv, void *user);
int32_t rte_ikcp_update(struct rte_ikcp *ikcp);
int32_t rte_ikcp_send(struct rte_ikcp *kcp, const char* data, int32_t len);
int32_t rte_ikcp_recv(struct rte_ikcp *kcp, char* data, int32_t len);
int32_t rte_ikcp_input(struct rte_ikcp *kcp, struct rte_mbuf *mbuf);
int32_t rte_ikcp_input_bulk(struct rte_ikcp *ikcp);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IKCP_H_ */