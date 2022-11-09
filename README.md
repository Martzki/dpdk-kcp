# dpdk-kcp
A kcp wrapper DPDK library.
## How to use
1. Put the source code to `lib` and modify the `meson.build`.  
```bash
cp librte_ikcp $RTE_SDK/lib
# Add 'ikcp' to libraries.
vi $RTE_SDK/lib/meson.build
```
2. Compile the lib.
```bash
cd $RTE_SDK/build
ninja
```
## API
1. `rte_ikcp` data structure.
A `rte_ikcp` structure contains internal ikcp structure, `rte_ikcp_config` structure and rx/tx queues used for multi-queue mode.
```C
/**
 * The RTE ikcp structure.
 */
struct rte_ikcp {
	ikcpcb kcp;                           /**< Internal kcp object. */
	struct rte_ikcp_config config;        /**< Internal config. */
	struct rte_ring *rx_queue, *tx_queue; /**< RX/TX queues when RTE_IKCP_MQ is enabled. */
};
```
2. `rte_ikcp_config` data structure.
This structure mainly describe what addresses, which port and which queue would be used to send.
Flags are defined in `rte_ikcp.h`, for example flags with `RTE_IKCP_MQ` will enable multi-queue mode.
```C
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
```
3. Create a `rte_ikcp` object.
This API create a `rte_ikcp` object with a given `rte_ikcp_config`, the `conv` and the `user` is used in internal `ikcp_create`, see `ikcp.h` and `ikcp.c` for more information. 
A `rte_ickp` is associated with a certain port after creating.
```C
struct rte_ikcp *rte_ikcp_create(struct rte_ikcp_config config, uint32_t conv, void *user);
```
4. Release a `rte_ikcp` object.
This API will release a `rte_ikcp` object which is created before.
When a port is released the `rte_ikcp` will be release as well by the `RTE_ETH_EVENT_DESTROY` callback.
```C
void rte_ikcp_release(struct rte_ikcp *ikcp);
```
5. Update internal kcp status.
This API will pass current timestamp to `kcp_update`. It should be invoked around every 10~100ms. Or use `rte_ikcp_check` to decied when to invoke.
```C
void rte_ikcp_update(struct rte_ikcp *ikcp);
```
6. Get the next tsc cycle when `rte_ikcp_update` should be invoked.
```C
uint64_t rte_ikcp_check(struct rte_ikcp *ikcp);
```
7. Send data to kcp.
This API will send data to internal kcp tx queue. The data will be sent by rte_ikcp_flush or rte_ikcp_update on most occations.
```C
int32_t rte_ikcp_send(struct rte_ikcp *ikcp, const char* data, int32_t len);
```
8. Recv data from kcp.
This API will recv data from kcp.
``` C
int32_t rte_ikcp_recv(struct rte_ikcp *ikcp, char* data, int32_t len);
```
9. Input data to internal kcp rx queue in single-queue mode.
The mbuf is checked whether belongs to the `rte_ikcp` or not and freed after enqueue sucessfully. 
``` bash
int32_t rte_ikcp_input(struct rte_ikcp *ikcp, struct rte_mbuf *mbuf);
``` 
10. Input data from multi mbufs from `rte_ikcp->rx_queue` in multi-queue mode.
The mbufs should be enqueued to the `rte_ikcp->rx_queue` already.
```C
int32_t rte_ikcp_input_bulk(struct rte_ikcp *ikcp);
```
11. Flush pending data of kcp.
This API directly invoke `ikcp_flush`. It should not be invoked directly on most occations.
```C
void rte_ikcp_flush(struct rte_ikcp *ikcp);
```
12. Set the internal params of a kcp.
This API directly invoke `ikcp_nodelay`. See `ikcp.h` for more information.
```C
void rte_ikcp_nodelay(struct rte_ikcp *ikcp, int32_t nodelay, int32_t interval, int32_t resend, int32_t nc);
```
13. Check the size of next message in the internal kcp rx queue.
This API directly invoke `ikcp_peeksize`. See `ikcp.h` for more information.
```C
int32_t rte_ikcp_peeksize(struct rte_ikcp *ikcp);
```
14. Set the internal MTU of a kcp.
This API directly invoke `ikcp_setmtu` and will be invoked in `rte_ikcp_create`.
```C
int32_t rte_ikcp_setmtu(struct rte_ikcp *ikcp, int32_t mtu);
```
15. Set the internal windows size of a kcp.
This API directly invoke `ikcp_wndsize`. See `ikcp.h` for more information.
```C
int32_t rte_ikcp_wndsize(struct rte_ikcp *ikcp, int32_t sndwnd, int32_t rcvwnd);
```
16. Get how many packet is waiting to be sent of a kcp.
This API directly invoke `ikcp_waitsnd`. See `ikcp.h` for more information.
```C
int32_t rte_ikcp_waitsnd(struct rte_ikcp *ikcp);
```
## Example
The example contains 2 modes with different kcp backend. 
Mode can be changed with `--dpdk-kcp` or `--socket-kcp`.
If you use linux kcp backend, the packet send/recv will use socket rather than `librte_ikcp`.
``` bash
[root@localhost examples]# ./dpdk-ikcp -h
Usage: ./dpdk-ikcp [options]
options:
  --socket-kcp: Use kcp socket backend
  --dpdk-kcp: Use kcp pmd backend
```
The available arguments are here:
```bash
# dpdk backend.
[root@localhost examples]# ./dpdk-ikcp --dpdk-kcp -- -h
./dpdk-ikcp --dpdk-kcp [EAL options] -- [--debug] [-4|-6] --device PCI --src SRC --dst DST --next-hop-mac M:M:M:M:M:M
                -4: Use IPv4 (default)
                -6: Use IPv6
                -v: Display verbose send/recv details
                --device: Assign the PCI address of device
                --src: Assign the source IP
                --dst: Assign the destination IP
                --next-hop-mac: Assign the MAC address of the next hop
                --multi-queue: Use multi queues to transmit
                --debug: Enable kcp private log
                
# socket backend.
[root@localhost examples]# ./dpdk-ikcp --socket-kcp -h
./dpdk-ikcp --socket-kcp [-4|-6] --dst DST
                -4: IP address is IPv4 (default)
                -6: IP address is IPv6
                -v: Display verbose send/recv details
                --src: Assign the source IP
                --dst: Assign the destination IP
```
And you can control the example to start/stop sending packets by commands `send`, `stop` and `exit`:
```bash
[root@localhost dpdk-kcp]# ./dpdk-ikcp --socket-kcp --dst 1.1.1.1 --src 1.1.1.2 -v
cli > timestamp: 1550194806 recv 0 pkts in last 1000 milliseconds.
timestamp: 1550195807 recv 0 pkts in last 1000 milliseconds.
timestamp: 1550196808 recv 0 pkts in last 1000 milliseconds.

cli > support commands: send stop exit
```
