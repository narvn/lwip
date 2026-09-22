/* SPDX-License-Identifier: BSD-3-Clause */
/** @file
 * IPv6 Path MTU discovery, independent of neighbor discovery.
 */
#ifndef LWIP_HDR_IP6_PMTU_H
#define LWIP_HDR_IP6_PMTU_H

#include "lwip/opt.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_IPV6 && LWIP_IPV6_PMTU
u16_t ip6_pmtu_get_mtu(const ip6_addr_t *dest, struct netif *netif, u16_t mtu);
void ip6_pmtu_input(struct pbuf *p, struct netif *netif);
void ip6_pmtu_track_packet(struct pbuf *p, struct netif *netif);
void ip6_pmtu_cleanup_netif(struct netif *netif);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_IP6_PMTU_H */
