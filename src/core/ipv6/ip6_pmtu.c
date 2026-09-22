/* SPDX-License-Identifier: BSD-3-Clause */
/** @file
 * IPv6 Path MTU discovery (RFC 8201).
 * Normal output only records paths. A timer exists only for learned PMTUs,
 * and runs at the next expiry rather than polling idle paths.
 */

#include "lwip/opt.h"

#if LWIP_IPV6 && LWIP_IPV6_PMTU

#include "lwip/ip6_pmtu.h"
#include "lwip/ip6.h"
#include "lwip/ip.h"
#include "lwip/prot/icmp6.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"

#if LWIP_IPV6_PMTU_ENTRIES < 1
#error "LWIP_IPV6_PMTU_ENTRIES must be positive"
#endif
#if LWIP_IPV6_PMTU_TIMEOUT < 300000UL || LWIP_IPV6_PMTU_TIMEOUT > 0x7fffffffUL
#error "LWIP_IPV6_PMTU_TIMEOUT must be between 5 minutes and 0x7fffffff ms"
#endif

struct ip6_pmtu_entry {
  struct netif *netif;
  ip6_addr_t source;
  ip6_addr_t destination;
  u32_t updated;
  /* Zero means that the path was used, but no PTB has reduced its MTU. */
  u16_t mtu;
};

static struct ip6_pmtu_entry ip6_pmtu_cache[LWIP_IPV6_PMTU_ENTRIES];

#if LWIP_TIMERS
static void
ip6_pmtu_timeout(void *arg)
{
  size_t i;
  u32_t now = sys_now();
  u32_t next = SYS_TIMEOUTS_SLEEPTIME_INFINITE;
  LWIP_UNUSED_ARG(arg);

  sys_untimeout(ip6_pmtu_timeout, NULL);
  for (i = 0; i < LWIP_ARRAYSIZE(ip6_pmtu_cache); i++) {
    struct ip6_pmtu_entry *entry = &ip6_pmtu_cache[i];
    if (entry->netif != NULL) {
      u32_t age = (u32_t)(now - entry->updated);
      if (age >= LWIP_IPV6_PMTU_TIMEOUT) {
        entry->netif = NULL;
      } else if (entry->mtu != 0) {
        next = LWIP_MIN(next, LWIP_IPV6_PMTU_TIMEOUT - age);
      }
    }
  }
  if (next != SYS_TIMEOUTS_SLEEPTIME_INFINITE) {
    sys_timeout(next, ip6_pmtu_timeout, NULL);
  }
}
#endif /* LWIP_TIMERS */

/** Apply the lowest unexpired estimate for this destination and interface. */
u16_t
ip6_pmtu_get_mtu(const ip6_addr_t *dest, struct netif *netif, u16_t mtu)
{
  size_t i;
  u32_t now = sys_now();

  LWIP_ASSERT_CORE_LOCKED();
  for (i = 0; i < LWIP_ARRAYSIZE(ip6_pmtu_cache); i++) {
    const struct ip6_pmtu_entry *entry = &ip6_pmtu_cache[i];
    if ((entry->netif == netif) && (entry->netif != NULL) &&
        (entry->mtu != 0) &&
        ((u32_t)(now - entry->updated) < LWIP_IPV6_PMTU_TIMEOUT) &&
        ip6_addr_cmp(&entry->destination, dest)) {
      mtu = LWIP_MIN(mtu, entry->mtu);
    }
  }
  return mtu;
}

/** Remember actual output paths so unsolicited PTBs cannot create entries.
 * Packet data is copied before returning; no pbuf is retained.
 */
void
ip6_pmtu_track_packet(struct pbuf *p, struct netif *netif)
{
  struct ip6_hdr header;
  ip6_addr_t source, destination;
  struct ip6_pmtu_entry *selected = NULL;
  u32_t now = sys_now();
  u32_t oldest = 0;
  size_t i;

  LWIP_ASSERT_CORE_LOCKED();
  if ((netif_mtu6(netif) < IP6_MIN_MTU_LENGTH) ||
      (pbuf_copy_partial(p, &header, IP6_HLEN, 0) != IP6_HLEN)) {
    return;
  }
  ip6_addr_copy_from_packed(source, header.src);
  ip6_addr_copy_from_packed(destination, header.dest);
  ip6_addr_assign_zone(&source, IP6_UNICAST, netif);
  ip6_addr_assign_zone(&destination, IP6_UNKNOWN, netif);
  if (ip6_addr_isany(&source) || ip6_addr_ismulticast(&source)) {
    return;
  }

  for (i = 0; i < LWIP_ARRAYSIZE(ip6_pmtu_cache); i++) {
    struct ip6_pmtu_entry *entry = &ip6_pmtu_cache[i];
    u32_t age = (u32_t)(now - entry->updated);
    if ((entry->netif == NULL) || (age >= LWIP_IPV6_PMTU_TIMEOUT)) {
      selected = entry;
      oldest = 0xffffffffUL;
    } else if ((entry->netif == netif) &&
               ip6_addr_cmp(&entry->source, &source) &&
               ip6_addr_cmp(&entry->destination, &destination)) {
      /* Sending must not postpone recovery from a learned, reduced PMTU. */
      if (entry->mtu == 0) {
        entry->updated = now;
      }
      return;
    } else if ((entry->mtu == 0) && ((selected == NULL) || (age > oldest))) {
      selected = entry;
      oldest = age;
    }
  }

  /* Do not evict a learned PMTU early merely to record another output path. */
  if (selected != NULL) {
    selected->netif = netif;
    ip6_addr_copy(selected->source, source);
    ip6_addr_copy(selected->destination, destination);
    selected->mtu = 0;
    selected->updated = now;
  }
}

/** Process an already checksum-validated ICMPv6 PTB. The caller owns p. */
void
ip6_pmtu_input(struct pbuf *p, struct netif *netif)
{
  struct icmp6_hdr icmp;
  struct ip6_hdr quoted;
  ip6_addr_t source, destination;
  u32_t mtu, now;
  size_t i;

  LWIP_ASSERT_CORE_LOCKED();
  if ((p->tot_len < sizeof(icmp) + IP6_HLEN + 8) ||
      (pbuf_copy_partial(p, &icmp, sizeof(icmp), 0) != sizeof(icmp)) ||
      (icmp.type != ICMP6_TYPE_PTB) || (icmp.code != 0) ||
      (pbuf_copy_partial(p, &quoted, IP6_HLEN, sizeof(icmp)) != IP6_HLEN) ||
      (IP6H_V(&quoted) != 6)) {
    return;
  }
  mtu = lwip_ntohl(icmp.data);
  /* RFC 8201: ignore values below the IPv6 minimum and never raise a PMTU
   * based on a PTB. The quoted packet must actually exceed the reported MTU.
   */
  if ((mtu < IP6_MIN_MTU_LENGTH) || (mtu >= netif_mtu6(netif)) ||
      (mtu >= (u32_t)IP6_HLEN + IP6H_PLEN(&quoted))) {
    return;
  }
  ip6_addr_copy_from_packed(source, quoted.src);
  ip6_addr_copy_from_packed(destination, quoted.dest);
  ip6_addr_assign_zone(&source, IP6_UNICAST, netif);
  ip6_addr_assign_zone(&destination, IP6_UNKNOWN, netif);
  /* Errors are returned to the source of the offending packet, not to an
   * arbitrary local or PRETEND address selected by the sender of the PTB.
   */
  if (!ip6_addr_cmp(&source, ip6_current_dest_addr())) {
    return;
  }
  now = sys_now();
  for (i = 0; i < LWIP_ARRAYSIZE(ip6_pmtu_cache); i++) {
    struct ip6_pmtu_entry *entry = &ip6_pmtu_cache[i];
    if ((entry->netif == netif) &&
        ((u32_t)(now - entry->updated) < LWIP_IPV6_PMTU_TIMEOUT) &&
        ip6_addr_cmp(&entry->source, &source) &&
        ip6_addr_cmp(&entry->destination, &destination)) {
      if ((entry->mtu == 0) || (mtu <= entry->mtu)) {
        entry->mtu = (u16_t)mtu;
        entry->updated = now;
#if LWIP_TIMERS
        ip6_pmtu_timeout(NULL);
#endif
      }
      return;
    }
  }
}

/** Forget paths when a netif goes down or is removed, before it can be freed. */
void
ip6_pmtu_cleanup_netif(struct netif *netif)
{
  size_t i;

  LWIP_ASSERT_CORE_LOCKED();
  for (i = 0; i < LWIP_ARRAYSIZE(ip6_pmtu_cache); i++) {
    if (ip6_pmtu_cache[i].netif == netif) {
      ip6_pmtu_cache[i].netif = NULL;
    }
  }
#if LWIP_TIMERS
  ip6_pmtu_timeout(NULL);
#endif
}

#endif /* LWIP_IPV6 && LWIP_IPV6_PMTU */
