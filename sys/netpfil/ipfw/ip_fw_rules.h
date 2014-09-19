#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/netpfil/ipfw/ip_fw2.c 243711 2012-11-30 19:36:55Z melifaro $");

/*
 * The FreeBSD IP packet firewall, main file
 */

#ifndef INET
#error "IPFIREWALL requires INET"
#endif /* INET */

#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>

#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_carp.h>
#include <netinet/pim.h>
#include <netinet/sctp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>
#ifdef INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/scope6_var.h>
#include <netinet6/ip6_var.h>
#endif

#include <netpfil/ipfw/ip_fw_private.h>

#include <machine/in_cksum.h>	/* XXX for in_cksum */

// Declarations of some needed structs.
struct mbuf;

struct ifnet;
struct in_addr;
struct ip;
struct ip_fw_args;
struct ip_fw_chain;
struct ip_fw;
struct _ipfw_insn;
struct _ipfw_insn_if;
struct _ipfw_dyn_rule;

#ifndef __FreeBSD__
	struct bsd_ucred;
#else
	struct ucred;
#endif

VNET_DEFINE(int, fw_verbose);

VNET_DEFINE(u_int32_t, set_disable);
#define	V_set_disable			VNET(set_disable)

static VNET_DEFINE(int, fw_deny_unknown_exthdrs);
#define	V_fw_deny_unknown_exthdrs	VNET(fw_deny_unknown_exthdrs)

static VNET_DEFINE(int, fw_permit_single_frag6) = 1;
#define	V_fw_permit_single_frag6	VNET(fw_permit_single_frag6)


/*
 * Some macros used in the various matching options.
 * L3HDR maps an ipv4 pointer into a layer3 header pointer of type T
 * Other macros just cast void * into the appropriate type
 */
#define	L3HDR(T, ip)	((T *)((u_int32_t *)(ip) + (ip)->ip_hl))
#define	TCP(p)		((struct tcphdr *)(p))
#define	SCTP(p)		((struct sctphdr *)(p))
#define	UDP(p)		((struct udphdr *)(p))
#define	ICMP(p)		((struct icmphdr *)(p))
#define	ICMP6(p)	((struct icmp6_hdr *)(p))

/* This macro needs the calling function to have a tablearg argument */
#define	IP_FW_ARG_TABLEARG(a)	(((a) == IP_FW_TABLEARG) ? tablearg : (a))

/*
 * PULLUP_TO(len, p, T) makes sure that len + sizeof(T) is contiguous,
 * then it sets p to point at the offset "len" in the mbuf. WARNING: the
 * pointer might become stale after other pullups (but we never use it
 * this way).
 * 
 * This is a modified version, since returns 1, insteaf of goto pullup_failed.
 */
#define PULLUP_TO(_len, p, T)	PULLUP_LEN(_len, p, sizeof(T))
#define PULLUP_LEN(_len, p, T)					\
do {								\
	int x = (_len) + T;					\
	if ((m)->m_len < x) {					\
		args->m = m = m_pullup(m, x);			\
		if (m == NULL)					\
			return (1);			\
	}							\
	p = (mtod(m, char *) + (_len));				\
} while (0)

int
inspect_pkt(struct ip_fw_args *args, struct ip *ip, struct mbuf *m, struct in_addr *src_ip, struct in_addr *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint16_t *etype, uint16_t *ext_hd, uint16_t *iplen, int *pktlen, int *is_ipv4, int *is_ipv6, u_int *hlen, uint8_t *proto, uint8_t *icmp6_type, u_short *ip6f_mf, u_short *offset, void *ulp)
{
	/*
	 * if we have an ether header,
	 */
	if (args->eh)
		*etype = ntohs(args->eh->ether_type);

	/* Identify IP packets and fill up variables. */
	if ((*pktlen) >= sizeof(struct ip6_hdr) &&
	    (args->eh == NULL || (*etype) == ETHERTYPE_IPV6) && ip->ip_v == 6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)ip;
		*is_ipv6 = 1;
		args->f_id.addr_type = 6;
		(*hlen) = sizeof(struct ip6_hdr);
		*proto = ip6->ip6_nxt;

		/* Search extension headers to find upper layer protocols */
		while (ulp == NULL && (*offset) == 0) {
			switch (*proto) {
			case IPPROTO_ICMPV6:
				PULLUP_TO((*hlen), ulp, struct icmp6_hdr);
				*icmp6_type = ICMP6(ulp)->icmp6_type;
				break;

			case IPPROTO_TCP:
				PULLUP_TO((*hlen), ulp, struct tcphdr);
				*dst_port = TCP(ulp)->th_dport;
				*src_port = TCP(ulp)->th_sport;
				/* save flags for dynamic rules */
				args->f_id._flags = TCP(ulp)->th_flags;
				break;

			case IPPROTO_SCTP:
				PULLUP_TO((*hlen), ulp, struct sctphdr);
				*src_port = SCTP(ulp)->src_port;
				*dst_port = SCTP(ulp)->dest_port;
				break;

			case IPPROTO_UDP:
				PULLUP_TO((*hlen), ulp, struct udphdr);
				*dst_port = UDP(ulp)->uh_dport;
				*src_port = UDP(ulp)->uh_sport;
				break;

			case IPPROTO_HOPOPTS:	/* RFC 2460 */
				PULLUP_TO((*hlen), ulp, struct ip6_hbh);
				*ext_hd |= EXT_HOPOPTS;
				(*hlen) += (((struct ip6_hbh *)ulp)->ip6h_len + 1) << 3;
				*proto = ((struct ip6_hbh *)ulp)->ip6h_nxt;
				ulp = NULL;
				break;

			case IPPROTO_ROUTING:	/* RFC 2460 */
				PULLUP_TO((*hlen), ulp, struct ip6_rthdr);
				switch (((struct ip6_rthdr *)ulp)->ip6r_type) {
				case 0:
					*ext_hd |= EXT_RTHDR0;
					break;
				case 2:
					*ext_hd |= EXT_RTHDR2;
					break;
				default:
					if (V_fw_verbose)
						printf("IPFW2: IPV6 - Unknown "
						    "Routing Header type(%d)\n",
						    ((struct ip6_rthdr *)
						    ulp)->ip6r_type);
					if (V_fw_deny_unknown_exthdrs)
					    return (IP_FW_DENY);
					break;
				}
				*ext_hd |= EXT_ROUTING;
				(*hlen) += (((struct ip6_rthdr *)ulp)->ip6r_len + 1) << 3;
				*proto = ((struct ip6_rthdr *)ulp)->ip6r_nxt;
				ulp = NULL;
				break;

			case IPPROTO_FRAGMENT:	/* RFC 2460 */
				PULLUP_TO((*hlen), ulp, struct ip6_frag);
				*ext_hd |= EXT_FRAGMENT;
				(*hlen) += sizeof (struct ip6_frag);
				*proto = ((struct ip6_frag *)ulp)->ip6f_nxt;
				*offset = ((struct ip6_frag *)ulp)->ip6f_offlg &
					IP6F_OFF_MASK;
				*ip6f_mf = ((struct ip6_frag *)ulp)->ip6f_offlg &
					IP6F_MORE_FRAG;
				if (V_fw_permit_single_frag6 == 0 &&
				    *offset == 0 && *ip6f_mf == 0) {
					if (V_fw_verbose)
						printf("IPFW2: IPV6 - Invalid "
						    "Fragment Header\n");
					if (V_fw_deny_unknown_exthdrs)
					    return (IP_FW_DENY);
					break;
				}
				args->f_id.extra =
				    ntohl(((struct ip6_frag *)ulp)->ip6f_ident);
				ulp = NULL;
				break;

			case IPPROTO_DSTOPTS:	/* RFC 2460 */
				PULLUP_TO((*hlen), ulp, struct ip6_hbh);
				*ext_hd |= EXT_DSTOPTS;
				(*hlen) += (((struct ip6_hbh *)ulp)->ip6h_len + 1) << 3;
				*proto = ((struct ip6_hbh *)ulp)->ip6h_nxt;
				ulp = NULL;
				break;

			case IPPROTO_AH:	/* RFC 2402 */
				PULLUP_TO((*hlen), ulp, struct ip6_ext);
				*ext_hd |= EXT_AH;
				(*hlen) += (((struct ip6_ext *)ulp)->ip6e_len + 2) << 2;
				*proto = ((struct ip6_ext *)ulp)->ip6e_nxt;
				ulp = NULL;
				break;

			case IPPROTO_ESP:	/* RFC 2406 */
				PULLUP_TO((*hlen), ulp, uint32_t);	/* SPI, Seq# */
				/* Anything past Seq# is variable length and
				 * data past this ext. header is encrypted. */
				*ext_hd |= EXT_ESP;
				break;

			case IPPROTO_NONE:	/* RFC 2460 */
				/*
				 * Packet ends here, and IPv6 header has
				 * already been pulled up. If ip6e_len!=0
				 * then octets must be ignored.
				 */
				ulp = ip; /* non-NULL to get out of loop. */
				break;

			case IPPROTO_OSPFIGP:
				/* XXX OSPF header check? */
				PULLUP_TO((*hlen), ulp, struct ip6_ext);
				break;

			case IPPROTO_PIM:
				/* XXX PIM header check? */
				PULLUP_TO((*hlen), ulp, struct pim);
				break;

			case IPPROTO_CARP:
				PULLUP_TO((*hlen), ulp, struct carp_header);
				if (((struct carp_header *)ulp)->carp_version !=
				    CARP_VERSION) 
					return (IP_FW_DENY);
				if (((struct carp_header *)ulp)->carp_type !=
				    CARP_ADVERTISEMENT) 
					return (IP_FW_DENY);
				break;

			case IPPROTO_IPV6:	/* RFC 2893 */
				PULLUP_TO((*hlen), ulp, struct ip6_hdr);
				break;

			case IPPROTO_IPV4:	/* RFC 2893 */
				PULLUP_TO((*hlen), ulp, struct ip);
				break;

			default:
				if (V_fw_verbose)
					printf("IPFW2: IPV6 - Unknown "
					    "Extension Header(%d), ext_hd=%x\n",
					     *proto, *ext_hd);
				if (V_fw_deny_unknown_exthdrs)
				    return (IP_FW_DENY);
				PULLUP_TO((*hlen), ulp, struct ip6_ext);
				break;
			} /*switch */
		}
		ip = mtod(m, struct ip *);
		ip6 = (struct ip6_hdr *)ip;
		args->f_id.src_ip6 = ip6->ip6_src;
		args->f_id.dst_ip6 = ip6->ip6_dst;
		args->f_id.src_ip = 0;
		args->f_id.dst_ip = 0;
		args->f_id.flow_id6 = ntohl(ip6->ip6_flow);
	} else if ((*pktlen) >= sizeof(struct ip) &&
	    (args->eh == NULL || (*etype) == ETHERTYPE_IP) && ip->ip_v == 4) {
	    	*is_ipv4 = 1;
		(*hlen) = ip->ip_hl << 2;
		args->f_id.addr_type = 4;

		/*
		 * Collect parameters into local variables for faster matching.
		 */
		*proto = ip->ip_p;
		*src_ip = ip->ip_src;
		*dst_ip = ip->ip_dst;
		*offset = ntohs(ip->ip_off) & IP_OFFMASK;
		*iplen = ntohs(ip->ip_len);
		*pktlen = *iplen < (*pktlen) ? *iplen : (*pktlen);

		if (*offset == 0) {
			switch (*proto) {
			case IPPROTO_TCP:
				PULLUP_TO((*hlen), ulp, struct tcphdr);
				*dst_port = TCP(ulp)->th_dport;
				*src_port = TCP(ulp)->th_sport;
				/* save flags for dynamic rules */
				args->f_id._flags = TCP(ulp)->th_flags;
				break;

			case IPPROTO_SCTP:
				PULLUP_TO((*hlen), ulp, struct sctphdr);
				*src_port = SCTP(ulp)->src_port;
				*dst_port = SCTP(ulp)->dest_port;
				break;

			case IPPROTO_UDP:
				PULLUP_TO((*hlen), ulp, struct udphdr);
				*dst_port = UDP(ulp)->uh_dport;
				*src_port = UDP(ulp)->uh_sport;
				break;

			case IPPROTO_ICMP:
				PULLUP_TO((*hlen), ulp, struct icmphdr);
				//args->f_id.flags = ICMP(ulp)->icmp_type;
				break;

			default:
				break;
			}
		}

		ip = mtod(m, struct ip *);
		args->f_id.src_ip = ntohl((*src_ip).s_addr);
		args->f_id.dst_ip = ntohl((*dst_ip).s_addr);
	}

	if (*proto) { /* we may have port numbers, store them */
		args->f_id.proto = *proto;
		args->f_id.src_port = *src_port = ntohs(*src_port);
		args->f_id.dst_port = *dst_port = ntohs(*dst_port);
	}
	
	return (0);
}

/*
 * Auxiliar functions.
 */
static int
icmptype_match(struct icmphdr *icmp, ipfw_insn_u32 *cmd)
{
	int type = icmp->icmp_type;

	return (type <= ICMP_MAXTYPE && (cmd->d[0] & (1<<type)) );
}

#define TT	( (1 << ICMP_ECHO) | (1 << ICMP_ROUTERSOLICIT) | \
    (1 << ICMP_TSTAMP) | (1 << ICMP_IREQ) | (1 << ICMP_MASKREQ) )

static int
is_icmp_query(struct icmphdr *icmp)
{
	int type = icmp->icmp_type;

	return (type <= ICMP_MAXTYPE && (TT & (1<<type)) );
}
#undef TT

/*
 * The following checks use two arrays of 8 or 16 bits to store the
 * bits that we want set or clear, respectively. They are in the
 * low and high half of cmd->arg1 or cmd->d[0].
 *
 * We scan options and store the bits we find set. We succeed if
 *
 *	(want_set & ~bits) == 0 && (want_clear & ~bits) == want_clear
 *
 * The code is sometimes optimized not to store additional variables.
 */

static int
flags_match(ipfw_insn *cmd, u_int8_t bits)
{
	u_char want_clear;
	bits = ~bits;

	if ( ((cmd->arg1 & 0xff) & bits) != 0)
		return 0; /* some bits we want set were clear */
	want_clear = (cmd->arg1 >> 8) & 0xff;
	if ( (want_clear & bits) != want_clear)
		return 0; /* some bits we want clear were set */
	return 1;
}

static int
ipopts_match(struct ip *ip, ipfw_insn *cmd)
{
	int optlen, bits = 0;
	u_char *cp = (u_char *)(ip + 1);
	int x = (ip->ip_hl << 2) - sizeof (struct ip);

	for (; x > 0; x -= optlen, cp += optlen) {
		int opt = cp[IPOPT_OPTVAL];

		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[IPOPT_OLEN];
			if (optlen <= 0 || optlen > x)
				return 0; /* invalid or truncated */
		}
		switch (opt) {

		default:
			break;

		case IPOPT_LSRR:
			bits |= IP_FW_IPOPT_LSRR;
			break;

		case IPOPT_SSRR:
			bits |= IP_FW_IPOPT_SSRR;
			break;

		case IPOPT_RR:
			bits |= IP_FW_IPOPT_RR;
			break;

		case IPOPT_TS:
			bits |= IP_FW_IPOPT_TS;
			break;
		}
	}
	return (flags_match(cmd, bits));
}

static int
tcpopts_match(struct tcphdr *tcp, ipfw_insn *cmd)
{
	int optlen, bits = 0;
	u_char *cp = (u_char *)(tcp + 1);
	int x = (tcp->th_off << 2) - sizeof(struct tcphdr);

	for (; x > 0; x -= optlen, cp += optlen) {
		int opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[1];
			if (optlen <= 0)
				break;
		}

		switch (opt) {

		default:
			break;

		case TCPOPT_MAXSEG:
			bits |= IP_FW_TCPOPT_MSS;
			break;

		case TCPOPT_WINDOW:
			bits |= IP_FW_TCPOPT_WINDOW;
			break;

		case TCPOPT_SACK_PERMITTED:
		case TCPOPT_SACK:
			bits |= IP_FW_TCPOPT_SACK;
			break;

		case TCPOPT_TIMESTAMP:
			bits |= IP_FW_TCPOPT_TS;
			break;

		}
	}
	return (flags_match(cmd, bits));
}

static int
iface_match(struct ifnet *ifp, ipfw_insn_if *cmd, struct ip_fw_chain *chain, uint32_t *tablearg)
{
	if (ifp == NULL)	/* no iface with this packet, match fails */
		return 0;
	/* Check by name or by IP address */
	if (cmd->name[0] != '\0') { /* match by name */
		if (cmd->name[0] == '\1') /* use tablearg to match */
			return ipfw_lookup_table_extended(chain, cmd->p.glob,
				ifp->if_xname, tablearg, IPFW_TABLE_INTERFACE);
		/* Check name */
		if (cmd->p.glob) {
			if (fnmatch(cmd->name, ifp->if_xname, 0) == 0)
				return(1);
		} else {
			if (strncmp(ifp->if_xname, cmd->name, IFNAMSIZ) == 0)
				return(1);
		}
	} else {
#if !defined(USERSPACE) && defined(__FreeBSD__)	/* and OSX too ? */
		struct ifaddr *ia;

		if_addr_rlock(ifp);
		TAILQ_FOREACH(ia, &ifp->if_addrhead, ifa_link) {
			if (ia->ifa_addr->sa_family != AF_INET)
				continue;
			if (cmd->p.ip.s_addr == ((struct sockaddr_in *)
			    (ia->ifa_addr))->sin_addr.s_addr) {
				if_addr_runlock(ifp);
				return(1);	/* match */
			}
		}
		if_addr_runlock(ifp);
#endif /* __FreeBSD__ */
	}
	return(0);	/* no match, fail ... */
}

/*
 * The verify_path function checks if a route to the src exists and
 * if it is reachable via ifp (when provided).
 * 
 * The 'verrevpath' option checks that the interface that an IP packet
 * arrives on is the same interface that traffic destined for the
 * packet's source address would be routed out of.
 * The 'versrcreach' option just checks that the source address is
 * reachable via any route (except default) in the routing table.
 * These two are a measure to block forged packets. This is also
 * commonly known as "anti-spoofing" or Unicast Reverse Path
 * Forwarding (Unicast RFP) in Cisco-ese. The name of the knobs
 * is purposely reminiscent of the Cisco IOS command,
 *
 *   ip verify unicast reverse-path
 *   ip verify unicast source reachable-via any
 *
 * which implements the same functionality. But note that the syntax
 * is misleading, and the check may be performed on all IP packets
 * whether unicast, multicast, or broadcast.
 */
static int
verify_path(struct in_addr src, struct ifnet *ifp, u_int fib)
{
#if defined(USERSPACE) || !defined(__FreeBSD__)
	return 0;
#else
	struct route ro;
	struct sockaddr_in *dst;

	bzero(&ro, sizeof(ro));

	dst = (struct sockaddr_in *)&(ro.ro_dst);
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	dst->sin_addr = src;
	in_rtalloc_ign(&ro, 0, fib);

	if (ro.ro_rt == NULL)
		return 0;

	/*
	 * If ifp is provided, check for equality with rtentry.
	 * We should use rt->rt_ifa->ifa_ifp, instead of rt->rt_ifp,
	 * in order to pass packets injected back by if_simloop():
	 * routing entry (via lo0) for our own address
	 * may exist, so we need to handle routing assymetry.
	 */
	if (ifp != NULL && ro.ro_rt->rt_ifa->ifa_ifp != ifp) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* if no ifp provided, check if rtentry is not default route */
	if (ifp == NULL &&
	     satosin(rt_key(ro.ro_rt))->sin_addr.s_addr == INADDR_ANY) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* or if this is a blackhole/reject route */
	if (ifp == NULL && ro.ro_rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* found valid route */
	RTFREE(ro.ro_rt);
	return 1;
#endif /* __FreeBSD__ */
}

#ifdef INET6
/*
 * ipv6 specific aux funtions here...
 */
static int
icmp6type_match (int type, ipfw_insn_u32 *cmd)
{
	return (type <= ICMP6_MAXTYPE && (cmd->d[type/32] & (1<<(type%32)) ) );
}

/* support for IP6_*_ME opcodes */
static int
search_ip6_addr_net (struct in6_addr * ip6_addr)
{
	struct ifnet *mdc;
	struct ifaddr *mdc2;
	struct in6_ifaddr *fdm;
	struct in6_addr copia;

	TAILQ_FOREACH(mdc, &V_ifnet, if_link) {
		if_addr_rlock(mdc);
		TAILQ_FOREACH(mdc2, &mdc->if_addrhead, ifa_link) {
			if (mdc2->ifa_addr->sa_family == AF_INET6) {
				fdm = (struct in6_ifaddr *)mdc2;
				copia = fdm->ia_addr.sin6_addr;
				/* need for leaving scope_id in the sock_addr */
				in6_clearscope(&copia);
				if (IN6_ARE_ADDR_EQUAL(ip6_addr, &copia)) {
					if_addr_runlock(mdc);
					return 1;
				}
			}
		}
		if_addr_runlock(mdc);
	}
	return 0;
}

static int
flow6id_match( int curr_flow, ipfw_insn_u32 *cmd )
{
	int i;
	for (i=0; i <= cmd->o.arg1; ++i )
		if (curr_flow == cmd->d[i] )
			return 1;
	return 0;
}

static int
verify_path6(struct in6_addr *src, struct ifnet *ifp, u_int fib)
{
	struct route_in6 ro;
	struct sockaddr_in6 *dst;

	bzero(&ro, sizeof(ro));

	dst = (struct sockaddr_in6 * )&(ro.ro_dst);
	dst->sin6_family = AF_INET6;
	dst->sin6_len = sizeof(*dst);
	dst->sin6_addr = *src;

	in6_rtalloc_ign(&ro, 0, fib);
	if (ro.ro_rt == NULL)
		return 0;

	/* 
	 * if ifp is provided, check for equality with rtentry
	 * We should use rt->rt_ifa->ifa_ifp, instead of rt->rt_ifp,
	 * to support the case of sending packets to an address of our own.
	 * (where the former interface is the first argument of if_simloop()
	 *  (=ifp), the latter is lo0)
	 */
	if (ifp != NULL && ro.ro_rt->rt_ifa->ifa_ifp != ifp) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* if no ifp provided, check if rtentry is not default route */
	if (ifp == NULL &&
	    IN6_IS_ADDR_UNSPECIFIED(&satosin6(rt_key(ro.ro_rt))->sin6_addr)) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* or if this is a blackhole/reject route */
	if (ifp == NULL && ro.ro_rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		RTFREE(ro.ro_rt);
		return 0;
	}

	/* found valid route */
	RTFREE(ro.ro_rt);
	return 1;

}

static int
is_icmp6_query(int icmp6_type)
{
	if ((icmp6_type <= ICMP6_MAXTYPE) &&
	    (icmp6_type == ICMP6_ECHO_REQUEST ||
	    icmp6_type == ICMP6_MEMBERSHIP_QUERY ||
	    icmp6_type == ICMP6_WRUREQUEST ||
	    icmp6_type == ICMP6_FQDN_QUERY ||
	    icmp6_type == ICMP6_NI_QUERY))
		return (1);

	return (0);
}

static void
send_reject6(struct ip_fw_args *args, int code, u_int hlen, struct ip6_hdr *ip6)
{
	struct mbuf *m;

	m = args->m;
	if (code == ICMP6_UNREACH_RST && args->f_id.proto == IPPROTO_TCP) {
		struct tcphdr *tcp;
		tcp = (struct tcphdr *)((char *)ip6 + hlen);

		if ((tcp->th_flags & TH_RST) == 0) {
			struct mbuf *m0;
			m0 = ipfw_send_pkt(args->m, &(args->f_id),
			    ntohl(tcp->th_seq), ntohl(tcp->th_ack),
			    tcp->th_flags | TH_RST);
			if (m0 != NULL)
				ip6_output(m0, NULL, NULL, 0, NULL, NULL,
				    NULL);
		}
		FREE_PKT(m);
	} else if (code != ICMP6_UNREACH_RST) { /* Send an ICMPv6 unreach. */
#if 0
		/*
		 * Unlike above, the mbufs need to line up with the ip6 hdr,
		 * as the contents are read. We need to m_adj() the
		 * needed amount.
		 * The mbuf will however be thrown away so we can adjust it.
		 * Remember we did an m_pullup on it already so we
		 * can make some assumptions about contiguousness.
		 */
		if (args->L3offset)
			m_adj(m, args->L3offset);
#endif
		icmp6_error(m, ICMP6_DST_UNREACH, code, 0);
	} else
		FREE_PKT(m);

	args->m = NULL;
}

#endif /* INET6 */


/*
 * sends a reject message, consuming the mbuf passed as an argument.
 */
static void
send_reject(struct ip_fw_args *args, int code, int iplen, struct ip *ip)
{

#if 0
	/* XXX When ip is not guaranteed to be at mtod() we will
	 * need to account for this */
	 * The mbuf will however be thrown away so we can adjust it.
	 * Remember we did an m_pullup on it already so we
	 * can make some assumptions about contiguousness.
	 */
	if (args->L3offset)
		m_adj(m, args->L3offset);
#endif
	if (code != ICMP_REJECT_RST) { /* Send an ICMP unreach */
		icmp_error(args->m, ICMP_UNREACH, code, 0L, 0);
	} else if (args->f_id.proto == IPPROTO_TCP) {
		struct tcphdr *const tcp =
		    L3HDR(struct tcphdr, mtod(args->m, struct ip *));
		if ( (tcp->th_flags & TH_RST) == 0) {
			struct mbuf *m;
			m = ipfw_send_pkt(args->m, &(args->f_id),
				ntohl(tcp->th_seq), ntohl(tcp->th_ack),
				tcp->th_flags | TH_RST);
			if (m != NULL)
				ip_output(m, NULL, NULL, 0, NULL, NULL);
		}
		FREE_PKT(args->m);
	} else
		FREE_PKT(args->m);
	args->m = NULL;
}

/*
 * Support for uid/gid/jail lookup. These tests are expensive
 * (because we may need to look into the list of active sockets)
 * so we cache the results. ugid_lookupp is 0 if we have not
 * yet done a lookup, 1 if we succeeded, and -1 if we tried
 * and failed. The function always returns the match value.
 * We could actually spare the variable and use *uc, setting
 * it to '(void *)check_uidgid if we have no info, NULL if
 * we tried and failed, or any other value if successful.
 */
static int
check_uidgid(ipfw_insn_u32 *insn, struct ip_fw_args *args, int *ugid_lookupp,
    struct ucred **uc)
{
#if defined(USERSPACE)
	return 0;	// not supported in userspace
#else
#ifndef __FreeBSD__
	/* XXX */
	return cred_check(insn, proto, oif,
	    dst_ip, dst_port, src_ip, src_port,
	    (struct bsd_ucred *)uc, ugid_lookupp, ((struct mbuf *)inp)->m_skb);
#else  /* FreeBSD */
	struct in_addr src_ip, dst_ip;
	struct inpcbinfo *pi;
	struct ipfw_flow_id *id;
	struct inpcb *pcb, *inp;
	struct ifnet *oif;
	int lookupflags;
	int match;

	id = &args->f_id;
	inp = args->inp;
	oif = args->oif;

	/*
	 * Check to see if the UDP or TCP stack supplied us with
	 * the PCB. If so, rather then holding a lock and looking
	 * up the PCB, we can use the one that was supplied.
	 */
	if (inp && *ugid_lookupp == 0) {
		INP_LOCK_ASSERT(inp);
		if (inp->inp_socket != NULL) {
			*uc = crhold(inp->inp_cred);
			*ugid_lookupp = 1;
		} else
			*ugid_lookupp = -1;
	}
	/*
	 * If we have already been here and the packet has no
	 * PCB entry associated with it, then we can safely
	 * assume that this is a no match.
	 */
	if (*ugid_lookupp == -1)
		return (0);
	if (id->proto == IPPROTO_TCP) {
		lookupflags = 0;
		pi = &V_tcbinfo;
	} else if (id->proto == IPPROTO_UDP) {
		lookupflags = INPLOOKUP_WILDCARD;
		pi = &V_udbinfo;
	} else
		return 0;
	lookupflags |= INPLOOKUP_RLOCKPCB;
	match = 0;
	if (*ugid_lookupp == 0) {
		if (id->addr_type == 6) {
#ifdef INET6
			if (oif == NULL)
				pcb = in6_pcblookup_mbuf(pi,
				    &id->src_ip6, htons(id->src_port),
				    &id->dst_ip6, htons(id->dst_port),
				    lookupflags, oif, args->m);
			else
				pcb = in6_pcblookup_mbuf(pi,
				    &id->dst_ip6, htons(id->dst_port),
				    &id->src_ip6, htons(id->src_port),
				    lookupflags, oif, args->m);
#else
			*ugid_lookupp = -1;
			return (0);
#endif
		} else {
			src_ip.s_addr = htonl(id->src_ip);
			dst_ip.s_addr = htonl(id->dst_ip);
			if (oif == NULL)
				pcb = in_pcblookup_mbuf(pi,
				    src_ip, htons(id->src_port),
				    dst_ip, htons(id->dst_port),
				    lookupflags, oif, args->m);
			else
				pcb = in_pcblookup_mbuf(pi,
				    dst_ip, htons(id->dst_port),
				    src_ip, htons(id->src_port),
				    lookupflags, oif, args->m);
		}
		if (pcb != NULL) {
			INP_RLOCK_ASSERT(pcb);
			*uc = crhold(pcb->inp_cred);
			*ugid_lookupp = 1;
			INP_RUNLOCK(pcb);
		}
		if (*ugid_lookupp == 0) {
			/*
			 * We tried and failed, set the variable to -1
			 * so we will not try again on this packet.
			 */
			*ugid_lookupp = -1;
			return (0);
		}
	}
	if (insn->o.opcode == O_UID)
		match = ((*uc)->cr_uid == (uid_t)insn->d[0]);
	else if (insn->o.opcode == O_GID)
		match = groupmember((gid_t)insn->d[0], *uc);
	else if (insn->o.opcode == O_JAIL)
		match = ((*uc)->cr_prison->pr_id == (int)insn->d[0]);
	return (match);
#endif /* __FreeBSD__ */
#endif /* not supported in userspace */
}

/*
 * Helper function to set args with info on the rule after the matching
 * one. slot is precise, whereas we guess rule_id as they are
 * assigned sequentially.
 */
static void
set_match(struct ip_fw_args *args, int slot,
    struct ip_fw_chain *chain)
{
	args->rule.chain_id = chain->id;
	args->rule.slot = slot + 1; /* we use 0 as a marker */
	args->rule.rule_id = 1 + chain->map[slot]->id;
	args->rule.rulenum = chain->map[slot]->rulenum;
}

/*
 * Helper function to enable cached rule lookups using
 * x_next and next_rule fields in ipfw rule.
 */
static int 
jump_fast(struct ip_fw_chain *chain, struct ip_fw *f, int num,
    int tablearg, int jump_backwards)
{
	int f_pos;

	/* If possible use cached f_pos (in f->next_rule),
	 * whose version is written in f->next_rule
	 * (horrible hacks to avoid changing the ABI).
	 */
	if (num != IP_FW_TABLEARG && (uintptr_t)f->x_next == chain->id)
		f_pos = (uintptr_t)f->next_rule;
	else {
		int i = IP_FW_ARG_TABLEARG(num);
		/* make sure we do not jump backward */
		if (jump_backwards == 0 && i <= f->rulenum)
			i = f->rulenum + 1;
		f_pos = ipfw_find_rule(chain, i, 0);
		/* update the cache */
		if (num != IP_FW_TABLEARG) {
			f->next_rule = (void *)(uintptr_t)f_pos;
			f->x_next = (void *)(uintptr_t)chain->id;
		}
	}

	return (f_pos);
}

/*
 * Actions executed per-rule.
 */

static IPFW_RULES_INLINE void
rule_nop(int *match)
{
	*match = 1;
}

static IPFW_RULES_INLINE void
rule_forward_mac(int opcode)
{
	printf("ipfw: opcode %d unimplemented\n",
		opcode);

}

static IPFW_RULES_INLINE void
rule_jail(int * match, u_short offset, uint8_t proto, ipfw_insn *cmd, struct ip_fw_args *args, int ucred_lookup, void *ucred_cache)
{
	/*
	 * We only check offset == 0 && proto != 0,
	 * as this ensures that we have a
	 * packet with the ports info.
	 */
	if (offset != 0)
		return;
	if (proto == IPPROTO_TCP ||
		proto == IPPROTO_UDP)
		*match = check_uidgid(
				(ipfw_insn_u32 *)cmd,
				args, &ucred_lookup,
#ifdef __FreeBSD__
				//(struct bsd_ucred **)&ucred_cache);
				(struct ucred **)&ucred_cache);
#else
				(void *)&ucred_cache);
#endif
}

static IPFW_RULES_INLINE void
rule_recv(int *match, ipfw_insn *cmd, struct mbuf *m, struct ip_fw_chain *chain, uint32_t *tablearg)
{
	*match = iface_match(m->m_pkthdr.rcvif, (ipfw_insn_if *)cmd, chain, tablearg);
}

static IPFW_RULES_INLINE void
rule_xmit(int *match, struct ifnet *oif, ipfw_insn *cmd, struct ip_fw_chain *chain, uint32_t *tablearg)
{
	*match = iface_match(oif, (ipfw_insn_if *)cmd, chain, tablearg);
}

static IPFW_RULES_INLINE void
rule_via(int *match, struct ifnet *oif, struct mbuf *m, ipfw_insn *cmd, struct ip_fw_chain *chain, uint32_t *tablearg)
{
	*match = iface_match(oif ? oif : m->m_pkthdr.rcvif, (ipfw_insn_if *)cmd, chain, tablearg);
}

static IPFW_RULES_INLINE void
rule_macaddr2(int *match, struct ip_fw_args *args, ipfw_insn *cmd)
{
	if (args->eh != NULL) {	/* have MAC header */
		u_int32_t *want = (u_int32_t *)
			((ipfw_insn_mac *)cmd)->addr;
		u_int32_t *mask = (u_int32_t *)
			((ipfw_insn_mac *)cmd)->mask;
		u_int32_t *hdr = (u_int32_t *)args->eh;

		*match =
		    ( want[0] == (hdr[0] & mask[0]) &&
		      want[1] == (hdr[1] & mask[1]) &&
		      want[2] == (hdr[2] & mask[2]) );
	}

}

static IPFW_RULES_INLINE void
rule_mac_type(int *match, struct ip_fw_args *args, ipfw_insn *cmd, int cmdlen, uint16_t etype)
{
	if (args->eh != NULL) {
		u_int16_t *p =
		    ((ipfw_insn_u16 *)cmd)->ports;
		int i;

		for (i = cmdlen - 1; !match && i>0;
		    i--, p += 2)
			*match = (etype >= p[0] &&
			    etype <= p[1]);
	}

}

static IPFW_RULES_INLINE void
rule_frag(int *match, u_short offset)
{
	*match = (offset != 0);
}

static IPFW_RULES_INLINE void
rule_in(int *match, struct ifnet *oif)
{
	/* "out" is "not in" */
	*match = (oif == NULL);
}

static IPFW_RULES_INLINE void
rule_layer2(int *match, struct ip_fw_args * args)
{
	*match = (args->eh != NULL);
}

static IPFW_RULES_INLINE void
rule_diverted(int *match, struct ip_fw_args * args, ipfw_insn *cmd)
{
	/* For diverted packets, args->rule.info
	 * contains the divert port (in host format)
	 * reason and direction.
	 */
	uint32_t i = args->rule.info;
	*match = (i&IPFW_IS_MASK) == IPFW_IS_DIVERT &&
	    cmd->arg1 & ((i & IPFW_INFO_IN) ? 1 : 2);
}

static IPFW_RULES_INLINE void
rule_proto(int *match, uint8_t proto, ipfw_insn *cmd)
{
	/*
	 * We do not allow an arg of 0 so the
	 * check of "proto" only suffices.
	 */
	*match = (proto == cmd->arg1);
}

static IPFW_RULES_INLINE void
rule_ip_src(int *match, int is_ipv4, ipfw_insn *cmd, struct in_addr *src_ip)
{
	*match = is_ipv4 &&
	    (((ipfw_insn_ip *)cmd)->addr.s_addr ==
	    src_ip->s_addr);
}

static IPFW_RULES_INLINE void
rule_ip_dst_lookup(int *match, ipfw_insn *cmd, int cmdlen, struct ip_fw_args *args, uint32_t *tablearg, int is_ipv4, int is_ipv6, struct ip *ip, struct in_addr *dst_ip, struct in_addr *src_ip, uint16_t dst_port, uint16_t src_port, u_short offset, uint8_t proto, int ucred_lookup, void *ucred_cache, struct ip_fw_chain *chain)
{
	if (is_ipv4) {
	    uint32_t key =
		(cmd->opcode == O_IP_DST_LOOKUP) ?
		    dst_ip->s_addr : src_ip->s_addr;
	    uint32_t v = 0;

	    if (cmdlen > F_INSN_SIZE(ipfw_insn_u32)) {
		/* generic lookup. The key must be
		 * in 32bit big-endian format.
		 */
		v = ((ipfw_insn_u32 *)cmd)->d[1];
		if (v == 0)
		    key = dst_ip->s_addr;
		else if (v == 1)
		    key = src_ip->s_addr;
		else if (v == 6) /* dscp */
		    key = (ip->ip_tos >> 2) & 0x3f;
		else if (offset != 0)
		    return;
		else if (proto != IPPROTO_TCP &&
			proto != IPPROTO_UDP)
		    return;
		else if (v == 2)
		    key = htonl(dst_port);
		else if (v == 3)
		    key = htonl(src_port);
#ifndef USERSPACE
		else if (v == 4 || v == 5) {
		    check_uidgid(
			(ipfw_insn_u32 *)cmd,
			args, &ucred_lookup,
#ifdef __FreeBSD__
			(struct ucred **)&ucred_cache);
		    if (v == 4 /* O_UID */)
			    key = ((struct ucred *)ucred_cache)->cr_uid;
		    else if (v == 5 /* O_JAIL */)
			    key = ((struct ucred *)ucred_cache)->cr_prison->pr_id;
#else /* !__FreeBSD__ */
			(void *)&ucred_cache);
		    if (v ==4 /* O_UID */)
			key = ucred_cache.uid;
		    else if (v == 5 /* O_JAIL */)
			key = ucred_cache.xid;
#endif /* !__FreeBSD__ */
		    key = htonl(key);
		} else
#endif /* !USERSPACE */
		    return;
	    }
	    *match = ipfw_lookup_table(chain,
		cmd->arg1, key, &v);
	    if (!(*match))
			return;
	    if (cmdlen == F_INSN_SIZE(ipfw_insn_u32))
		*match =
		    ((ipfw_insn_u32 *)cmd)->d[0] == v;
	    else
		*tablearg = v;
	} else if (is_ipv6) {
		uint32_t v = 0;
		void *pkey = (cmd->opcode == O_IP_DST_LOOKUP) ?
			&args->f_id.dst_ip6: &args->f_id.src_ip6;
		*match = ipfw_lookup_table_extended(chain,
				cmd->arg1, pkey, &v,
				IPFW_TABLE_CIDR);
		if (cmdlen == F_INSN_SIZE(ipfw_insn_u32))
			*match = ((ipfw_insn_u32 *)cmd)->d[0] == v;
		if (*match)
			*tablearg = v;
	}
}

static IPFW_RULES_INLINE void
rule_ip_dst_mask(int *match, int is_ipv4, ipfw_insn *cmd, int cmdlen, struct in_addr *dst_ip, struct in_addr *src_ip)
{
	if (is_ipv4) {
	    uint32_t a =
		(cmd->opcode == O_IP_DST_MASK) ?
		    dst_ip->s_addr : src_ip->s_addr;
	    uint32_t *p = ((ipfw_insn_u32 *)cmd)->d;
	    int i = cmdlen-1;

	    for (; !match && i>0; i-= 2, p+= 2)
		*match = (p[0] == (a & p[1]));
	}
}

static IPFW_RULES_INLINE void
rule_ip_src_me(int *match, int is_ipv4, int is_ipv6, struct in_addr *src_ip, struct ip_fw_args *args)
{
	if (is_ipv4) {
		struct ifnet *tif;

		INADDR_TO_IFP(*src_ip, tif);
		*match = (tif != NULL);
		return;
	}
#ifdef INET6
	/* also added to the next function */
	*match= is_ipv6 && search_ip6_addr_net(&args->f_id.src_ip6);
#endif /* INET6 */
}

#ifdef INET6
static IPFW_RULES_INLINE void
rule_ip6_src_me(int *match, int is_ipv6, struct ip_fw_args *args)
{
	*match= is_ipv6 && search_ip6_addr_net(&args->f_id.src_ip6);
}
#endif /* INET6 */

static IPFW_RULES_INLINE void
rule_ip_src_set(int *match, int is_ipv4, ipfw_insn *cmd, struct ip_fw_args *args)
{
	if (is_ipv4) {
		u_int32_t *d = (u_int32_t *)(cmd+1);
		u_int32_t addr =
		    cmd->opcode == O_IP_DST_SET ?
			args->f_id.dst_ip :
			args->f_id.src_ip;

		    if (addr < d[0])
			    return;
		    addr -= d[0]; /* subtract base */
		    *match = (addr < cmd->arg1) &&
			( d[ 1 + (addr>>5)] &
			  (1<<(addr & 0x1f)) );
	}
}

static IPFW_RULES_INLINE void
rule_ip_dst(int *match, int is_ipv4, ipfw_insn *cmd, struct in_addr *dst_ip)
{
	*match = is_ipv4 &&
	    (((ipfw_insn_ip *)cmd)->addr.s_addr ==
	    dst_ip->s_addr);
}

static IPFW_RULES_INLINE void
rule_ip_dst_me(int *match, struct ip_fw_args *args, int is_ipv4, int is_ipv6, struct in_addr *dst_ip)
{
	if (is_ipv4) {
		struct ifnet *tif;

		INADDR_TO_IFP(*dst_ip, tif);
		*match = (tif != NULL);
		return;
	}
#ifdef INET6
	*match= is_ipv6 && search_ip6_addr_net(&args->f_id.dst_ip6);
#endif /* INET6 */
}

#ifdef INET6
static IPFW_RULES_INLINE void
rule_ip6_dst_me(int *match, struct ip_fw_args *args, int is_ipv6)
{
	*match= is_ipv6 && search_ip6_addr_net(&args->f_id.dst_ip6);
}
#endif /* INET6 */

static IPFW_RULES_INLINE void
rule_ip_dstport(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, int cmdlen, uint16_t dst_port, uint16_t src_port)
{
	/*
	 * offset == 0 && proto != 0 is enough
	 * to guarantee that we have a
	 * packet with port info.
	 */
	if ((proto==IPPROTO_UDP || proto==IPPROTO_TCP)
	    && offset == 0) {
		u_int16_t x =
		    (cmd->opcode == O_IP_SRCPORT) ?
			src_port : dst_port ;
		u_int16_t *p =
		    ((ipfw_insn_u16 *)cmd)->ports;
		int i;

		for (i = cmdlen - 1; !match && i>0;
		    i--, p += 2)
			*match = (x>=p[0] && x<=p[1]);
	}
}

static IPFW_RULES_INLINE void
rule_icmptype(int *match, u_short offset, uint8_t proto, void *ulp, ipfw_insn *cmd )
{
	*match = (offset == 0 && proto==IPPROTO_ICMP &&
	    icmptype_match(ICMP(ulp), (ipfw_insn_u32 *)cmd) );
}

#ifdef INET6
static IPFW_RULES_INLINE void
rule_icmp6type(int *match, u_short offset, int is_ipv6, uint8_t proto, void *ulp, ipfw_insn *cmd)
{
	*match = is_ipv6 && offset == 0 &&
	    proto==IPPROTO_ICMPV6 &&
	    icmp6type_match(
		    ICMP6((void *)ulp)->icmp6_type,
		    (ipfw_insn_u32 *)cmd);
}
#endif /* INET6 */


static IPFW_RULES_INLINE void
rule_ipopt(int *match, int is_ipv4, struct ip *ip, ipfw_insn *cmd)
{
	*match = (is_ipv4 &&
    	ipopts_match(ip, cmd) );

}

static IPFW_RULES_INLINE void
rule_ipver(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
{
	*match = (is_ipv4 &&
		cmd->arg1 == ip->ip_v);
}

static IPFW_RULES_INLINE void
rule_ipttl(int *match, int is_ipv4, ipfw_insn *cmd, int cmdlen, struct ip *ip, uint16_t iplen)
{
	if (is_ipv4) {	/* only for IP packets */
	    uint16_t x;
	    uint16_t *p;
	    int i;

	    if (cmd->opcode == O_IPLEN)
			x = iplen;
	    else if (cmd->opcode == O_IPTTL)
			x = ip->ip_ttl;
	    else /* must be IPID */
			x = ntohs(ip->ip_id);
	    if (cmdlen == 1) {
			*match = (cmd->arg1 == x);
			return;
	    }
	    /* otherwise we have ranges */
	    p = ((ipfw_insn_u16 *)cmd)->ports;
	    i = cmdlen - 1;
	    for (; !match && i>0; i--, p += 2)
			*match = (x >= p[0] && x <= p[1]);
	}
}

static IPFW_RULES_INLINE void
rule_ipprecedence(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
{
	*match = (is_ipv4 &&
	    (cmd->arg1 == (ip->ip_tos & 0xe0)) );
}

static IPFW_RULES_INLINE void
rule_iptos(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
{
	*match = (is_ipv4 &&
	    flags_match(cmd, ip->ip_tos));
}

static IPFW_RULES_INLINE void
rule_dscp(int *match, int is_ipv4, int is_ipv6, ipfw_insn *cmd, struct ip *ip)
{
	uint32_t *p;
	uint16_t x;

	p = ((ipfw_insn_u32 *)cmd)->d;

	if (is_ipv4)
		x = ip->ip_tos >> 2;
	else if (is_ipv6) {
		uint8_t *v;
		v = &((struct ip6_hdr *)ip)->ip6_vfc;
		x = (*v & 0x0F) << 2;
		v++;
		x |= *v >> 6;
	} else
		return;

	/* DSCP bitmask is stored as low_u32 high_u32 */
	if (x > 32)
		*match = *(p + 1) & (1 << (x - 32));
	else
		*match = *p & (1 << x);
}

static IPFW_RULES_INLINE void
rule_tcpdatalen(int *match, uint8_t proto, u_short offset, void *ulp, uint16_t iplen, int cmdlen, ipfw_insn *cmd, struct ip *ip)
{
	if (proto == IPPROTO_TCP && offset == 0) {
	    struct tcphdr *tcp;
	    uint16_t x;
	    uint16_t *p;
	    int i;

	    tcp = TCP(ulp);
	    x = iplen -
		    ((ip->ip_hl + tcp->th_off) << 2);
	    if (cmdlen == 1) {
			*match = (cmd->arg1 == x);
			return;
	    }
	    /* otherwise we have ranges */
	    p = ((ipfw_insn_u16 *)cmd)->ports;
	    i = cmdlen - 1;
	    for (; !match && i>0; i--, p += 2)
			*match = (x >= p[0] && x <= p[1]);
	}
}

static IPFW_RULES_INLINE void
rule_tcpflags(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
{
	*match = (proto == IPPROTO_TCP && offset == 0 &&
	    flags_match(cmd, TCP(ulp)->th_flags));
}

static IPFW_RULES_INLINE int
rule_tcpopts(int *match, u_int hlen, void *ulp, uint8_t proto, u_short offset, ipfw_insn *cmd, struct mbuf *m, struct ip_fw_args *args)
{
	PULLUP_TO(hlen, ulp , (TCP(ulp)->th_off << 2));

	*match = (proto == IPPROTO_TCP && offset == 0 &&
	    tcpopts_match(TCP(ulp), cmd));
	return (0);
}

static IPFW_RULES_INLINE void
rule_tcpseq(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
{
	*match = (proto == IPPROTO_TCP && offset == 0 &&
	    ((ipfw_insn_u32 *)cmd)->d[0] ==
		TCP(ulp)->th_seq);
}

static IPFW_RULES_INLINE void
rule_tcpack(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
{
	*match = (proto == IPPROTO_TCP && offset == 0 &&
	    ((ipfw_insn_u32 *)cmd)->d[0] ==
		TCP(ulp)->th_ack);
}

static IPFW_RULES_INLINE void
rule_tcpwin(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, int cmdlen, void *ulp)
{
	if (proto == IPPROTO_TCP && offset == 0) {
	    uint16_t x;
	    uint16_t *p;
	    int i;

	    x = ntohs(TCP(ulp)->th_win);
	    if (cmdlen == 1) {
			*match = (cmd->arg1 == x);
			return;
	    }
	    /* Otherwise we have ranges. */
	    p = ((ipfw_insn_u16 *)cmd)->ports;
	    i = cmdlen - 1;
	    for (; !(*match) && i > 0; i--, p += 2)
		*match = (x >= p[0] && x <= p[1]);
	}
}

static IPFW_RULES_INLINE void
rule_estab(int *match, uint8_t proto, u_short offset, void *ulp)
{
	/* reject packets which have SYN only */
	/* XXX should i also check for TH_ACK ? */
	*match = (proto == IPPROTO_TCP && offset == 0 &&
	    (TCP(ulp)->th_flags &
	     (TH_RST | TH_ACK | TH_SYN)) != TH_SYN);
}

static IPFW_RULES_INLINE void
rule_altq(int *match, ipfw_insn *cmd, struct mbuf *m, struct ip *ip)
{
	struct pf_mtag *at;
	struct m_tag *mtag;
	ipfw_insn_altq *altq = (ipfw_insn_altq *)cmd;

	/*
	 * ALTQ uses mbuf tags from another
	 * packet filtering system - pf(4).
	 * We allocate a tag in its format
	 * and fill it in, pretending to be pf(4).
	 */
	*match = 1;
	at = pf_find_mtag(m);
	if (at != NULL && at->qid != 0)
		return;
	mtag = m_tag_get(PACKET_TAG_PF,
		sizeof(struct pf_mtag), M_NOWAIT | M_ZERO);
	if (mtag == NULL) {
		/*
		 * Let the packet fall back to the
		 * default ALTQ.
		 */
		return;
	}
	m_tag_prepend(m, mtag);
	at = (struct pf_mtag *)(mtag + 1);
	at->qid = altq->qid;
	at->hdr = ip;
}

static IPFW_RULES_INLINE void
rule_log(int *match, struct ip_fw *f, u_int hlen, struct ip_fw_args *args, struct mbuf *m, struct ifnet *oif, u_short offset, u_short ip6f_mf, uint32_t tablearg, struct ip *ip)
{
	ipfw_log(f, hlen, args, m,
		oif, offset | ip6f_mf, tablearg, ip);
	*match = 1;
}

static IPFW_RULES_INLINE void
rule_prob(int *match, ipfw_insn *cmd)
{
	*match = (random()<((ipfw_insn_u32 *)cmd)->d[0]);
	return;
}

static IPFW_RULES_INLINE void
rule_verrevpath(int *match, struct ifnet *oif, struct mbuf *m, int is_ipv6, struct ip_fw_args *args, struct in_addr *src_ip)
{
	/* Outgoing packets automatically pass/match */
	*match = ((oif != NULL) ||
	    (m->m_pkthdr.rcvif == NULL) ||
	    (
#ifdef INET6
	    is_ipv6 ?
		verify_path6(&(args->f_id.src_ip6),
		    m->m_pkthdr.rcvif, args->f_id.fib) :
#endif
	    verify_path(*src_ip, m->m_pkthdr.rcvif,
	        args->f_id.fib)));
}

static IPFW_RULES_INLINE void
rule_versrcreach(int *match, u_int hlen, struct ifnet *oif, int is_ipv6, struct ip_fw_args *args, struct in_addr *src_ip)
{
	/* Outgoing packets automatically pass/match */
	*match = (hlen > 0 && ((oif != NULL) ||
#ifdef INET6
	    is_ipv6 ?
	        verify_path6(&(args->f_id.src_ip6),
	            NULL, args->f_id.fib) :
#endif
	    verify_path(*src_ip, NULL, args->f_id.fib)));
}

static IPFW_RULES_INLINE void
rule_antispoof(int *match, struct ifnet *oif, u_int hlen, int is_ipv4, int is_ipv6, struct in_addr *src_ip, struct ip_fw_args *args, struct mbuf *m)
{
	/* Outgoing packets automatically pass/match */
	if (oif == NULL && hlen > 0 &&
	    (  (is_ipv4 && in_localaddr(*src_ip))
#ifdef INET6
	    || (is_ipv6 &&
	        in6_localaddr(&(args->f_id.src_ip6)))
#endif
	    ))
		*match =
#ifdef INET6
		    is_ipv6 ? verify_path6(
		        &(args->f_id.src_ip6),
		        m->m_pkthdr.rcvif,
			args->f_id.fib) :
#endif
		    verify_path(*src_ip,
		    	m->m_pkthdr.rcvif,
		        args->f_id.fib);
	else
		*match = 1;
}

#ifdef IPSEC
static IPFW_RULES_INLINE void
rule_ipsec(int *match, struct mbuf *)
{
	*match = (m_tag_find(m,
	    PACKET_TAG_IPSEC_IN_DONE, NULL) != NULL);
}
#endif /* IPSEC */

#ifdef INET6
static IPFW_RULES_INLINE void
rule_ip6_src(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
{
	*match = is_ipv6 &&
	    IN6_ARE_ADDR_EQUAL(&args->f_id.src_ip6,
	    &((ipfw_insn_ip6 *)cmd)->addr6);
}

static IPFW_RULES_INLINE void
rule_ip6_dst(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
{
	*match = is_ipv6 &&
	IN6_ARE_ADDR_EQUAL(&args->f_id.dst_ip6,
	    &((ipfw_insn_ip6 *)cmd)->addr6);
}

static IPFW_RULES_INLINE void
rule_ip6_dst_mask(int *match, struct ip_fw_args *args, ipfw_insn *cmd, int cmdlen, int is_ipv6)
{
	if (is_ipv6) {
		int i = cmdlen - 1;
		struct in6_addr p;
		struct in6_addr *d =
		    &((ipfw_insn_ip6 *)cmd)->addr6;

		for (; !(*match) && i > 0; d += 2,
		    i -= F_INSN_SIZE(struct in6_addr)
		    * 2) {
			p = (cmd->opcode ==
			    O_IP6_SRC_MASK) ?
			    args->f_id.src_ip6:
			    args->f_id.dst_ip6;
			APPLY_MASK(&p, &d[1]);
			*match =
			    IN6_ARE_ADDR_EQUAL(&d[0],
			    &p);
		}
	}
}

static IPFW_RULES_INLINE void
rule_flow6id(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
{
	*match = is_ipv6 &&
	    flow6id_match(args->f_id.flow_id6,
	    (ipfw_insn_u32 *) cmd);
}

static IPFW_RULES_INLINE void
rule_ext_hdr(int *match, int is_ipv6, uint16_t ext_hd, ipfw_insn *cmd)
{
	*match = is_ipv6 &&
	    (ext_hd & ((ipfw_insn *) cmd)->arg1);
}

static IPFW_RULES_INLINE void
rule_ip6(int *match, int is_ipv6)
{
	*match = is_ipv6;
}
#endif /* INET6 */

static IPFW_RULES_INLINE void
rule_ip4(int *match, int is_ipv4)
{
	*match = is_ipv4;
}

static IPFW_RULES_INLINE void
rule_tag(int *match, ipfw_insn *cmd, struct mbuf *m, uint32_t tablearg)
{
	struct m_tag *mtag;
	uint32_t tag = IP_FW_ARG_TABLEARG(cmd->arg1);

	/* Packet is already tagged with this tag? */
	mtag = m_tag_locate(m, MTAG_IPFW, tag, NULL);

	/* We have `untag' action when F_NOT flag is
	 * present. And we must remove this mtag from
	 * mbuf and reset `match' to zero (`match' will
	 * be inversed later).
	 * Otherwise we should allocate new mtag and
	 * push it into mbuf.
	 */
	if (cmd->len & F_NOT) { /* `untag' action */
		if (mtag != NULL)
			m_tag_delete(m, mtag);
		*match = 0;
	} else {
		if (mtag == NULL) {
			mtag = m_tag_alloc( MTAG_IPFW,
			    tag, 0, M_NOWAIT);
			if (mtag != NULL)
				m_tag_prepend(m, mtag);
		}
		*match = 1;
	}
}

static IPFW_RULES_INLINE void
rule_fib(int *match, struct ip_fw_args *args, ipfw_insn *cmd)
{
	if (args->f_id.fib == cmd->arg1)
		*match = 1;
}

static IPFW_RULES_INLINE void
rule_sockarg(int *match, int is_ipv6, uint8_t proto, struct in_addr *dst_ip, struct in_addr *src_ip, uint16_t dst_port, uint16_t src_port, struct ip_fw_args *args, uint32_t *tablearg)
{
#ifndef USERSPACE	/* not supported in userspace */
	struct inpcb *inp = args->inp;
	struct inpcbinfo *pi;
	
	if (is_ipv6) /* XXX can we remove this ? */
		return;

	if (proto == IPPROTO_TCP)
		pi = &V_tcbinfo;
	else if (proto == IPPROTO_UDP)
		pi = &V_udbinfo;
	else
		return;

	/*
	 * XXXRW: so_user_cookie should almost
	 * certainly be inp_user_cookie?
	 */

	/* For incomming packet, lookup up the 
	inpcb using the src/dest ip/port tuple */
	if (inp == NULL) {
		inp = in_pcblookup(pi, 
			*src_ip, htons(src_port),
			*dst_ip, htons(dst_port),
			INPLOOKUP_RLOCKPCB, NULL);
		if (inp != NULL) {
			*tablearg =
			    inp->inp_socket->so_user_cookie;
			if (*tablearg)
				*match = 1;
			INP_RUNLOCK(inp);
		}
	} else {
		if (inp->inp_socket) {
			*tablearg =
			    inp->inp_socket->so_user_cookie;
			if (*tablearg)
				*match = 1;
		}
	}
#endif /* !USERSPACE */
}

static IPFW_RULES_INLINE void
rule_tagged(int *match, ipfw_insn *cmd, int cmdlen, struct mbuf *m, uint32_t tablearg)
{
	struct m_tag *mtag;
	uint32_t tag = IP_FW_ARG_TABLEARG(cmd->arg1);

	if (cmdlen == 1) {
		*match = m_tag_locate(m, MTAG_IPFW,
		    tag, NULL) != NULL;
		return;
	}

	/* we have ranges */
	for (mtag = m_tag_first(m);
	    mtag != NULL && !(*match);
	    mtag = m_tag_next(m, mtag)) {
		uint16_t *p;
		int i;

		if (mtag->m_tag_cookie != MTAG_IPFW)
			continue;

		p = ((ipfw_insn_u16 *)cmd)->ports;
		i = cmdlen - 1;
		for(; !(*match) && i > 0; i--, p += 2)
			*match =
			    mtag->m_tag_id >= p[0] &&
			    mtag->m_tag_id <= p[1];
	}
}

/*
 * The second sets of opcodes. They represent the actions of a rule.
 */
static IPFW_RULES_INLINE void
rule_keep_state(int *match, struct ip_fw *f, ipfw_insn *cmd, struct ip_fw_args *args, uint32_t tablearg, int *retval, int *l, int *done)
{
	if (ipfw_install_state(f,
	    (ipfw_insn_limit *)cmd, args, tablearg)) {
		/* error or limit violation */
		*retval = IP_FW_DENY;
		*l = 0;	/* exit inner loop */
		*done = 1; /* exit outer loop */
	}
	*match = 1;
}

static IPFW_RULES_INLINE void
rule_check_state(int *match, int *dyn_dir, ipfw_dyn_rule *q, struct ip_fw_args *args, uint8_t proto, void *ulp, int pktlen, struct ip_fw *f, int *f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, int *cmdlen, int *l)
{
	/*
	 * dynamic rules are checked at the first
	 * keep-state or check-state occurrence,
	 * with the result being stored in dyn_dir.
	 * The compiler introduces a PROBE_STATE
	 * instruction for us when we have a
	 * KEEP_STATE (because PROBE_STATE needs
	 * to be run first).
	 */
	if (*dyn_dir == MATCH_UNKNOWN &&
	    (q = ipfw_lookup_dyn_rule(&args->f_id,
	     dyn_dir, proto == IPPROTO_TCP ?
		TCP(ulp) : NULL))
		!= NULL) {
		/*
		 * Found dynamic entry, update stats
		 * and jump to the 'action' part of
		 * the parent rule by setting
		 * f, cmd, l and clearing cmdlen.
		 */
		IPFW_INC_DYN_COUNTER(q, pktlen);
		/* XXX we would like to have f_pos
		 * readily accessible in the dynamic
	         * rule, instead of having to
		 * lookup q->rule.
		 */
		f = q->rule;
		*f_pos = ipfw_find_rule(chain,
			f->rulenum, f->id);
		cmd = ACTION_PTR(f);
		*l = f->cmd_len - f->act_ofs;
		ipfw_dyn_unlock(q);
		*cmdlen = 0;
		*match = 1;
		return;
	}
	/*
	 * Dynamic entry not found. If CHECK_STATE,
	 * skip to next rule, if PROBE_STATE just
	 * ignore and continue with next opcode.
	 */
	if (cmd->opcode == O_CHECK_STATE)
		*l = 0;	/* exit inner loop */
	*match = 1;
}

static IPFW_RULES_INLINE void
rule_accept(int *retval, int *l, int *done)
{
	*retval = 0;	/* accept */
	*l = 0;		/* exit inner loop */
	*done = 1;	/* exit outer loop */
}

static IPFW_RULES_INLINE void
rule_queue(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
{
	set_match(args, f_pos, chain);
	args->rule.info = IP_FW_ARG_TABLEARG(cmd->arg1);
	if (cmd->opcode == O_PIPE)
		args->rule.info |= IPFW_IS_PIPE;
	if (V_fw_one_pass)
		args->rule.info |= IPFW_ONEPASS;
	*retval = IP_FW_DUMMYNET;
	*l = 0;          /* exit inner loop */
	*done = 1;       /* exit outer loop */
}

static IPFW_RULES_INLINE void
rule_tee(int *l, int *done, int *retval, ipfw_insn *cmd, struct ip_fw_args *args, int f_pos, uint32_t tablearg, struct ip_fw_chain *chain)
{
	if (args->eh) /* not on layer 2 */
	    return;
	/* otherwise this is terminal */
	*l = 0;		/* exit inner loop */
	*done = 1;	/* exit outer loop */
	*retval = (cmd->opcode == O_DIVERT) ?
		IP_FW_DIVERT : IP_FW_TEE;
	set_match(args, f_pos, chain);
	args->rule.info = IP_FW_ARG_TABLEARG(cmd->arg1);
}

static IPFW_RULES_INLINE void
rule_count(int *l, struct ip_fw *f, int pktlen)
{
	IPFW_INC_RULE_COUNTER(f, pktlen);
	*l = 0;		/* exit inner loop */
}

static IPFW_RULES_INLINE void
rule_skipto(int *match, int *l, ipfw_insn *cmd, int *cmdlen, int *skip_or, int *f_pos, struct ip_fw *f, int pktlen, struct ip_fw_chain *chain, uint32_t tablearg)
{
    IPFW_INC_RULE_COUNTER(f, pktlen);
    *f_pos = jump_fast(chain, f, cmd->arg1, tablearg, 0);
    /*
     * Skip disabled rules, and re-enter
     * the inner loop with the correct
     * f_pos, f, l and cmd.
     * Also clear cmdlen and skip_or
     */
    for (; (*f_pos) < chain->n_rules - 1 &&
	    (V_set_disable &
	     (1 << chain->map[(*f_pos)]->set));
	    (*f_pos)++)
	;
    /* Re-enter the inner loop at the skipto rule. */
    f = chain->map[(*f_pos)];
    *l = f->cmd_len;
    cmd = f->cmd;
    *match = 1;
    *cmdlen = 0;
    *skip_or = 0;
}

static IPFW_RULES_INLINE void
rule_callreturn(ipfw_insn *cmd, struct mbuf *m, struct ip_fw *f, struct ip_fw_chain *chain, uint32_t tablearg, int pktlen, int *skip_or, int *cmdlen, int *f_pos, int *l)
{
	/*
	 * Implementation of `subroutine' call/return,
	 * in the stack carried in an mbuf tag. This
	 * is different from `skipto' in that any call
	 * address is possible (`skipto' must prevent
	 * backward jumps to avoid endless loops).
	 * We have `return' action when F_NOT flag is
	 * present. The `m_tag_id' field is used as
	 * stack pointer.
	 */
	struct m_tag *mtag;
	uint16_t jmpto, *stack;

#define	IS_CALL		((cmd->len & F_NOT) == 0)
#define	IS_RETURN	((cmd->len & F_NOT) != 0)
	/*
	 * Hand-rolled version of m_tag_locate() with
	 * wildcard `type'.
	 * If not already tagged, allocate new tag.
	 */
	mtag = m_tag_first(m);
	while (mtag != NULL) {
		if (mtag->m_tag_cookie ==
		    MTAG_IPFW_CALL)
			return;
		mtag = m_tag_next(m, mtag);
	}
	if (mtag == NULL && IS_CALL) {
		mtag = m_tag_alloc(MTAG_IPFW_CALL, 0,
		    IPFW_CALLSTACK_SIZE *
		    sizeof(uint16_t), M_NOWAIT);
		if (mtag != NULL)
			m_tag_prepend(m, mtag);
	}

	/*
	 * On error both `call' and `return' just
	 * continue with next rule.
	 */
	if (IS_RETURN && (mtag == NULL ||
	    mtag->m_tag_id == 0)) {
		l = 0;		/* exit inner loop */
		return;
	}
	if (IS_CALL && (mtag == NULL ||
	    mtag->m_tag_id >= IPFW_CALLSTACK_SIZE)) {
		printf("ipfw: call stack error, "
		    "go to next rule\n");
		l = 0;		/* exit inner loop */
		return;
	}

	IPFW_INC_RULE_COUNTER(f, pktlen);
	stack = (uint16_t *)(mtag + 1);

	/*
	 * The `call' action may use cached f_pos
	 * (in f->next_rule), whose version is written
	 * in f->next_rule.
	 * The `return' action, however, doesn't have
	 * fixed jump address in cmd->arg1 and can't use
	 * cache.
	 */
	if (IS_CALL) {
		stack[mtag->m_tag_id] = f->rulenum;
		mtag->m_tag_id++;
    		(*f_pos) = jump_fast(chain, f, cmd->arg1,
		    tablearg, 1);
	} else {	/* `return' action */
		mtag->m_tag_id--;
		jmpto = stack[mtag->m_tag_id] + 1;
		(*f_pos) = ipfw_find_rule(chain, jmpto, 0);
	}

	/*
	 * Skip disabled rules, and re-enter
	 * the inner loop with the correct
	 * f_pos, f, l and cmd.
	 * Also clear cmdlen and skip_or
	 */
	for (; (*f_pos) < chain->n_rules - 1 &&
	    (V_set_disable &
	    (1 << chain->map[(*f_pos)]->set)); (*f_pos)++)
		;
	/* Re-enter the inner loop at the dest rule. */
	f = chain->map[(*f_pos)];
	*l = f->cmd_len;
	cmd = f->cmd;
	*cmdlen = 0;
	*skip_or = 0;
#undef IS_CALL
#undef IS_RETURN
}

static IPFW_RULES_INLINE void
rule_reject(u_int hlen, int is_ipv4, u_short offset, uint8_t proto, void *ulp, struct mbuf *m, struct in_addr *dst_ip, struct ip_fw_args *args, ipfw_insn *cmd, uint16_t iplen, struct ip *ip)
{
	/*
	 * Drop the packet and send a reject notice
	 * if the packet is not ICMP (or is an ICMP
	 * query), and it is not multicast/broadcast.
	 */
	if (hlen > 0 && is_ipv4 && offset == 0 &&
	    (proto != IPPROTO_ICMP ||
	     is_icmp_query(ICMP(ulp))) &&
	    !(m->m_flags & (M_BCAST|M_MCAST)) &&
	    !IN_MULTICAST(ntohl(dst_ip->s_addr))) {
		send_reject(args, cmd->arg1, iplen, ip);
		m = args->m;
	}
}

#ifdef INET6
static IPFW_RULES_INLINE void
rule_unreach6(u_int hlen, int is_ipv6, u_short offset, uint8_t proto, uint8_t icmp6_type, struct mbuf *m, struct ip_fw_args *args, ipfw_insn *cmd, struct ip *ip)
{
	if (hlen > 0 && is_ipv6 &&
	    ((offset & IP6F_OFF_MASK) == 0) &&
	    (proto != IPPROTO_ICMPV6 ||
	     (is_icmp6_query(icmp6_type) == 1)) &&
	    !(m->m_flags & (M_BCAST|M_MCAST)) &&
	    !IN6_IS_ADDR_MULTICAST(&args->f_id.dst_ip6)) {
		send_reject6(
		    args, cmd->arg1, hlen,
		    (struct ip6_hdr *)ip);
		m = args->m;
	}
}
#endif /* INET6 */


static IPFW_RULES_INLINE void
rule_deny(int *l, int *done, int *retval)
{
	*retval = IP_FW_DENY;
	*l = 0;		/* exit inner loop */
	*done = 1;	/* exit outer loop */
}

static IPFW_RULES_INLINE void
rule_forward_ip(struct ip_fw_args *args, ipfw_dyn_rule *q, struct ip_fw *f, int dyn_dir, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
{
	if (args->eh)	/* not valid on layer2 pkts */
		return;
	if (q == NULL || q->rule != f ||
	    dyn_dir == MATCH_FORWARD) {
	    struct sockaddr_in *sa;
	    sa = &(((ipfw_insn_sa *)cmd)->sa);
	    if (sa->sin_addr.s_addr == INADDR_ANY) {
		bcopy(sa, &args->hopstore,
				sizeof(*sa));
		args->hopstore.sin_addr.s_addr =
			    htonl(tablearg);
		args->next_hop = &args->hopstore;
	    } else {
		args->next_hop = sa;
	    }
	}
	*retval = IP_FW_PASS;
	*l = 0;          /* exit inner loop */
	*done = 1;       /* exit outer loop */
}

#ifdef INET6
static IPFW_RULES_INLINE void
rule_forward_ip6(struct ip_fw_args *args, ipfw_dyn_rule *q, struct ip_fw *f, int dyn_dir, ipfw_insn *cmd, int *retval, int *l, int *done)
{
	if (args->eh)	/* not valid on layer2 pkts */
		return;
	if (q == NULL || q->rule != f ||
	    dyn_dir == MATCH_FORWARD) {
		struct sockaddr_in6 *sin6;

		sin6 = &(((ipfw_insn_sa6 *)cmd)->sa);
		args->next_hop6 = sin6;
	}
	*retval = IP_FW_PASS;
	*l = 0;		/* exit inner loop */
	*done = 1;	/* exit outer loop */
}
#endif /* INET6 */

static IPFW_RULES_INLINE void
rule_ngtee(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
{
	set_match(args, f_pos, chain);
	args->rule.info = IP_FW_ARG_TABLEARG(cmd->arg1);
	if (V_fw_one_pass)
		args->rule.info |= IPFW_ONEPASS;
	*retval = (cmd->opcode == O_NETGRAPH) ?
	    IP_FW_NETGRAPH : IP_FW_NGTEE;
	*l = 0;          /* exit inner loop */
	*done = 1;       /* exit outer loop */
}

static IPFW_RULES_INLINE void
rule_setfib(struct ip_fw *f, int pktlen, uint32_t tablearg, ipfw_insn *cmd, struct mbuf *m, struct ip_fw_args *args, int *l)
{
	uint32_t fib;

	IPFW_INC_RULE_COUNTER(f, pktlen);
	fib = IP_FW_ARG_TABLEARG(cmd->arg1);
	if (fib >= rt_numfibs)
		fib = 0;
	M_SETFIB(m, fib);
	args->f_id.fib = fib;
	*l = 0;		/* exit inner loop */
}

static IPFW_RULES_INLINE void
rule_setdscp(ipfw_insn *cmd, struct ip *ip, int is_ipv4, int is_ipv6, uint32_t tablearg, struct ip_fw *f, int pktlen, int *l)
{
	uint16_t code;

	code = IP_FW_ARG_TABLEARG(cmd->arg1) & 0x3F;
	l = 0;		/* exit inner loop */
	if (is_ipv4) {
		uint16_t a;

		a = ip->ip_tos;
		ip->ip_tos = (code << 2) | (ip->ip_tos & 0x03);
		a += ntohs(ip->ip_sum) - ip->ip_tos;
		ip->ip_sum = htons(a);
	} else if (is_ipv6) {
		uint8_t *v;

		v = &((struct ip6_hdr *)ip)->ip6_vfc;
		*v = (*v & 0xF0) | (code >> 2);
		v++;
		*v = (*v & 0x3F) | ((code & 0x03) << 6);
	} else
		return;

	IPFW_INC_RULE_COUNTER(f, pktlen);
}

static IPFW_RULES_INLINE void
rule_nat(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, struct mbuf *m, uint32_t tablearg, int *retval, int *done, int *l)
{
	*l = 0;          /* exit inner loop */
	*done = 1;       /* exit outer loop */
 				if (!IPFW_NAT_LOADED) {
	    *retval = IP_FW_DENY;
	    return;
	}

	struct cfg_nat *t;
	int nat_id;

	set_match(args, f_pos, chain);
	/* Check if this is 'global' nat rule */
	if (cmd->arg1 == 0) {
		*retval = ipfw_nat_ptr(args, NULL, m);
		return;
	}
	t = ((ipfw_insn_nat *)cmd)->nat;
	if (t == NULL) {
		nat_id = IP_FW_ARG_TABLEARG(cmd->arg1);
		t = (*lookup_nat_ptr)(&chain->nat, nat_id);

		if (t == NULL) {
		    *retval = IP_FW_DENY;
		    return;
		}
		if (cmd->arg1 != IP_FW_TABLEARG)
		    ((ipfw_insn_nat *)cmd)->nat = t;
	}
	*retval = ipfw_nat_ptr(args, t, m);
}

static IPFW_RULES_INLINE void
rule_reass(struct ip_fw *f, int f_pos, struct ip_fw_chain *chain, int pktlen, struct ip *ip, struct ip_fw_args *args, struct mbuf *m, int *retval, int *done, int *l)
{
	int ip_off;

	IPFW_INC_RULE_COUNTER(f, pktlen);
	*l = 0;	/* in any case exit inner loop */
	ip_off = ntohs(ip->ip_off);

	/* if not fragmented, go to next rule */
	if ((ip_off & (IP_MF | IP_OFFMASK)) == 0)
	    return;

	args->m = m = ip_reass(m);

	/*
	 * do IP header checksum fixup.
	 */
	if (m == NULL) { /* fragment got swallowed */
	    *retval = IP_FW_DENY;
	} else { /* good, packet complete */
	    int hlen;

	    ip = mtod(m, struct ip *);
	    hlen = ip->ip_hl << 2;
	    ip->ip_sum = 0;
	    if (hlen == sizeof(struct ip))
			ip->ip_sum = in_cksum_hdr(ip);
	    else
			ip->ip_sum = in_cksum(m, hlen);
		*retval = IP_FW_REASS;
		set_match(args, f_pos, chain);
	}
	*done = 1;	/* exit outer loop */
}
