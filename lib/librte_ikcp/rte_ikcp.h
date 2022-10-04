#ifndef _RTE_IKCP_H_
#define _RTE_IKCP_H_

#include <stdint.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_net.h>
#include "ikcp.h"

#define MAX_IKCP_PER_PORT 16

#define RTE_IKCP_USED               (1 << 0) /**< The ikcp structure is used or not. */
#define RTE_IKCP_L3_TYPE_IPV4       (1 << 1) /**< The kcp is using IPv4. */
#define RTE_IKCP_L3_TYPE_IPV6       (1 << 2) /**< The kcp is using IPv6. */
#define RTE_IKCP_ENABLE_PRIVATE_LOG (1 << 3) /**< Enable kcp internal log. */
#define RTE_IKCP_MQ                 (1 << 4) /**< Send/recv using multi queues. */

#define RTE_IKCP_L3_TYPE_MASK (RTE_IKCP_L3_TYPE_IPV4 | RTE_IKCP_L3_TYPE_IPV6)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The RTE ikcp config structure.
 */
struct rte_ikcp_config {
	uint16_t port_id;                   /**< Port id. */
	uint16_t txq_id;                    /**< TX queue id of the port, used when RTE_IKCP_MQ is disabled. */
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	} src_ip, dst_ip;                   /**< Addresses to send and receive. */
	uint16_t src_port;                  /**< UDP port when sending. */
	uint16_t dst_port;                  /**< UDP port when receiving. */
	struct rte_ether_addr self_mac;     /**< MAC address of the port. */
	struct rte_ether_addr next_hop_mac; /**< MAC address of the next hop. */
	struct rte_mempool *mempool;        /**< The mempool to allocate mbufs. */
	uint32_t flags;                     /**< Config flags. */
};

/**
 * The RTE ikcp structure.
 */
struct rte_ikcp {
	ikcpcb kcp;                           /**< Internal kcp object. */
	struct rte_ikcp_config config;        /**< Internal config. */
	struct rte_ring *rx_queue, *tx_queue; /**< RX/TX queues when RTE_IKCP_MQ is enabled. */
};

/**
 * Create an ikcp object.
 *
 * @param config
 *   Config structure of the ikcp object.
 * @param conv
 *   Conversation id between kcp endpoints and it must be unique for a specified conversation.
 * @param user
 *   User specified pointer and will be used in kcp output.
 * @return
 *   - The pointer of the ikcp object.
 *   - NULL on failure.
 */
struct rte_ikcp *rte_ikcp_create(struct rte_ikcp_config config, uint32_t conv, void *user);

/**
 * Release an ikcp object.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 */
void rte_ikcp_release(struct rte_ikcp *ikcp);

/**
 * Get the next tsc cycle when rte_ikcp_update should be invoked.
 *
 * It's important to reduce unnacessary ikcp_update invoking
 * when handling massive kcp connections.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @return
 *   The tsc cycle when rte_ikcp_update should be invoked.
 */
uint64_t rte_ikcp_check(struct rte_ikcp *ikcp);

/**
 * Update kcp interval state.
 *
 * Handle the data from internal kcp rx/tx queues and it should be
 * invoked around every 10~100ms. Or use rte_ikcp_check to decied when
 * to invoke.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 */
void rte_ikcp_update(struct rte_ikcp *ikcp);

/**
 * Send data to a kcp.
 *
 * It will allocate a mbuf and enqueue to internal kcp tx queue.
 * The data will be sent by rte_ikcp_flush or rte_ikcp_update on most occations.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param data
 *   The data will be sent.
 * @param len
 *   The length of the data.
 * @retrun
 *   - 0 on sucess.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_send(struct rte_ikcp *ikcp, const char* data, int32_t len);

/**
 * Receive data from a kcp.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param data
 *   The buffer to save the data.
 * @param len
 *   The length of the data.
 * @return
 *   - The length of data received.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_recv(struct rte_ikcp *ikcp, char* data, int32_t len);

/**
 * Enqueue the data of the mbuf to the kcp internal rx queue.
 *
 * The mbuf is checked whether belongs to the kcp or not and freed
 * after enqueue sucessfully.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param mbuf
 *   The mbuf contains data to be input to the kcp.
 * @return
 *   - 0 on sucess.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_input(struct rte_ikcp *ikcp, struct rte_mbuf *mbuf);

/**
 * Enqueue multi mbufs to the kcp internal rx queue.
 *
 * Invoke after mbufs were enqueued to the ikcp->rx_queue to support multi
 * rx/tx queues of a port.
 * Only invoke when RTE_IKCP_MQ is set.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @return
 *   - 0 on sucess.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_input_bulk(struct rte_ikcp *ikcp);

/**
 * Flush pending data of a kcp.
 *
 * It will be invoked in rte_ikcp_update and should not be invoked directly on
 * most occations.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 */
void rte_ikcp_flush(struct rte_ikcp *ikcp);

/**
 * Set the internal params of a kcp.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param nodelay
 *   Delay mode. 0 on disable, 1 on enable.
 * @param interval
 *   Internal update timer interval in millisec, default is 100ms
 * @param resend
 *   Fast resend is enable or not. 0 on disable, 1 on enable.
 * @param nc
 *   Congestion control mode. 0 on normal mode, 1 on congestion control disabled.
 */
void rte_ikcp_nodelay(struct rte_ikcp *ikcp, int32_t nodelay, int32_t interval, int32_t resend, int32_t nc);

/**
 * Check the size of next message in the internal kcp rx queue.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @return
 *   The size of the next message.
 */
int32_t rte_ikcp_peeksize(struct rte_ikcp *ikcp);

/**
 * Set the internal MTU of a kcp.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param mtu
 *   The MTU to be set.
 * @return
 *   - 0 on sucess.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_setmtu(struct rte_ikcp *ikcp, int32_t mtu);

/**
 * Set the internal windows size of a kcp.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @param sndwnd
 *   Send window size. Notice the size is the number of packets.
 * @param rcvwnd
 *   Send window size. Notice the size is the number of packets.
 * @return
 *   - 0 on sucess.
 *   - Less than 0 on failure.
 */
int32_t rte_ikcp_wndsize(struct rte_ikcp *ikcp, int32_t sndwnd, int32_t rcvwnd);

/**
 * Get how many packet is waiting to be sent of a kcp.
 *
 * @param ikcp
 *   The pointer of an ikcp object.
 * @return
 *   The number of packets are waiting to be sent.
 */
int32_t rte_ikcp_waitsnd(struct rte_ikcp *ikcp);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IKCP_H_ */