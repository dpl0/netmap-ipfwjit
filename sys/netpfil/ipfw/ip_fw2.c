/*-
 * Copyright (c) 2002-2009 Luigi Rizzo, Universita` di Pisa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/netpfil/ipfw/ip_fw2.c 243711 2012-11-30 19:36:55Z melifaro $");

/*
 * The FreeBSD IP packet firewall, main file
 */

#include "opt_ipfw.h"
#include "opt_ipdivert.h"
#include "opt_inet.h"
#ifndef INET
#error "IPFIREWALL requires INET"
#endif /* INET */
#include "opt_inet6.h"
#include "opt_ipsec.h"
#define IPFW_RULES_INLINE __always_inline
#include "ip_fw_rules.h"
#include "jit.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/jail.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/ucred.h>
#include <net/ethernet.h> /* for ETHERTYPE_IP */
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netpfil/pf/pf_mtag.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_carp.h>
#include <netinet/pim.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/sctp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#ifdef INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/scope6_var.h>
#include <netinet6/ip6_var.h>
#endif

#include <netpfil/ipfw/ip_fw_private.h>

#include <machine/in_cksum.h>	/* XXX for in_cksum */

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

/*
 * static variables followed by global ones.
 * All ipfw global variables are here.
 */

/* ipfw_vnet_ready controls when we are open for business */
VNET_DEFINE(int, ipfw_vnet_ready) = 0;
#define	V_ipfw_vnet_ready	VNET(ipfw_vnet_ready)

static VNET_DEFINE(int, fw_deny_unknown_exthdrs);
#define	V_fw_deny_unknown_exthdrs	VNET(fw_deny_unknown_exthdrs)

#ifdef IPFIREWALL_DEFAULT_TO_ACCEPT
static int default_to_accept = 1;
#else
static int default_to_accept;
#endif

VNET_DEFINE(int, autoinc_step);
VNET_DEFINE(int, fw_one_pass) = 1;

VNET_DEFINE(unsigned int, fw_tables_max);
/* Use 128 tables by default */
static unsigned int default_fw_tables = IPFW_TABLES_DEFAULT;

/*
 * Each rule belongs to one of 32 different sets (0..31).
 * The variable set_disable contains one bit per set.
 * If the bit is set, all rules in the corresponding set
 * are disabled. Set RESVD_SET(31) is reserved for the default rule
 * and rules that are not deleted by the flush command,
 * and CANNOT be disabled.
 * Rules in set RESVD_SET can only be deleted individually.
 */
VNET_DEFINE(u_int32_t, set_disable);
#define	V_set_disable			VNET(set_disable)

VNET_DEFINE(int, fw_verbose);
/* counter for ipfw_log(NULL...) */
VNET_DEFINE(u_int64_t, norule_counter);
VNET_DEFINE(int, verbose_limit);

/* layer3_chain contains the list of rules for layer 3 */
VNET_DEFINE(struct ip_fw_chain, layer3_chain);

VNET_DEFINE(int, ipfw_nat_ready) = 0;

ipfw_nat_t *ipfw_nat_ptr = NULL;
struct cfg_nat *(*lookup_nat_ptr)(struct nat_list *, int);
ipfw_nat_cfg_t *ipfw_nat_cfg_ptr;
ipfw_nat_cfg_t *ipfw_nat_del_ptr;
ipfw_nat_cfg_t *ipfw_nat_get_cfg_ptr;
ipfw_nat_cfg_t *ipfw_nat_get_log_ptr;

#ifdef SYSCTL_NODE
uint32_t dummy_def = IPFW_DEFAULT_RULE;
static int sysctl_ipfw_table_num(SYSCTL_HANDLER_ARGS);

SYSBEGIN(f3)

SYSCTL_NODE(_net_inet_ip, OID_AUTO, fw, CTLFLAG_RW, 0, "Firewall");
SYSCTL_VNET_INT(_net_inet_ip_fw, OID_AUTO, one_pass,
    CTLFLAG_RW | CTLFLAG_SECURE3, &VNET_NAME(fw_one_pass), 0,
    "Only do a single pass through ipfw when using dummynet(4)");
SYSCTL_VNET_INT(_net_inet_ip_fw, OID_AUTO, autoinc_step,
    CTLFLAG_RW, &VNET_NAME(autoinc_step), 0,
    "Rule number auto-increment step");
SYSCTL_VNET_INT(_net_inet_ip_fw, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_SECURE3, &VNET_NAME(fw_verbose), 0,
    "Log matches to ipfw rules");
SYSCTL_VNET_INT(_net_inet_ip_fw, OID_AUTO, verbose_limit,
    CTLFLAG_RW, &VNET_NAME(verbose_limit), 0,
    "Set upper limit of matches of ipfw rules logged");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, default_rule, CTLFLAG_RD,
    &dummy_def, 0,
    "The default/max possible rule number.");
SYSCTL_VNET_PROC(_net_inet_ip_fw, OID_AUTO, tables_max,
    CTLTYPE_UINT|CTLFLAG_RW, 0, 0, sysctl_ipfw_table_num, "IU",
    "Maximum number of tables");
SYSCTL_INT(_net_inet_ip_fw, OID_AUTO, default_to_accept, CTLFLAG_RDTUN,
    &default_to_accept, 0,
    "Make the default rule accept all packets.");
TUNABLE_INT("net.inet.ip.fw.default_to_accept", &default_to_accept);
TUNABLE_INT("net.inet.ip.fw.tables_max", (int *)&default_fw_tables);
SYSCTL_VNET_INT(_net_inet_ip_fw, OID_AUTO, static_count,
    CTLFLAG_RD, &VNET_NAME(layer3_chain.n_rules), 0,
    "Number of static rules");

#ifdef INET6
SYSCTL_DECL(_net_inet6_ip6);
SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, fw, CTLFLAG_RW, 0, "Firewall");
SYSCTL_VNET_INT(_net_inet6_ip6_fw, OID_AUTO, deny_unknown_exthdrs,
    CTLFLAG_RW | CTLFLAG_SECURE, &VNET_NAME(fw_deny_unknown_exthdrs), 0,
    "Deny packets with unknown IPv6 Extension Headers");
SYSCTL_VNET_INT(_net_inet6_ip6_fw, OID_AUTO, permit_single_frag6,
    CTLFLAG_RW | CTLFLAG_SECURE, &VNET_NAME(fw_permit_single_frag6), 0,
    "Permit single packet IPv6 fragments");
#endif /* INET6 */

SYSEND

#endif /* SYSCTL_NODE */


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

/*
 * The main check routine for the firewall.
 *
 * All arguments are in args so we can modify them and return them
 * back to the caller.
 *
 * Parameters:
 *
 *	args->m	(in/out) The packet; we set to NULL when/if we nuke it.
 *		Starts with the IP header.
 *	args->eh (in)	Mac header if present, NULL for layer3 packet.
 *	args->L3offset	Number of bytes bypassed if we came from L2.
 *			e.g. often sizeof(eh)  ** NOTYET **
 *	args->oif	Outgoing interface, NULL if packet is incoming.
 *		The incoming interface is in the mbuf. (in)
 *	args->divert_rule (in/out)
 *		Skip up to the first rule past this rule number;
 *		upon return, non-zero port number for divert or tee.
 *
 *	args->rule	Pointer to the last matching rule (in/out)
 *	args->next_hop	Socket we are forwarding to (out).
 *	args->next_hop6	IPv6 next hop we are forwarding to (out).
 *	args->f_id	Addresses grabbed from the packet (out)
 * 	args->rule.info	a cookie depending on rule action
 *
 * Return value:
 *
 *	IP_FW_PASS	the packet must be accepted
 *	IP_FW_DENY	the packet must be dropped
 *	IP_FW_DIVERT	divert packet, port in m_tag
 *	IP_FW_TEE	tee packet, port in m_tag
 *	IP_FW_DUMMYNET	to dummynet, pipe in args->cookie
 *	IP_FW_NETGRAPH	into netgraph, cookie args->cookie
 *		args->rule contains the matching rule,
 *		args->rule.info has additional information.
 *
 */
int
ipfw_chk(struct ip_fw_args *args)
{
	struct ip_fw_chain *chain = &V_layer3_chain;

	/* Read comment below about this variable. */
	struct mbuf *m = args->m;

	if (m->m_flags & M_SKIP_FIREWALL || (! V_ipfw_vnet_ready))
		return (IP_FW_PASS);	/* accept */

	args->f_id.fib = M_GETFIB(m); /* note mbuf not altered) */

	/*
	 * Local variables holding state while processing a packet:
	 *
	 * IMPORTANT NOTE: to speed up the processing of rules, there
	 * are some assumption on the values of the variables, which
	 * are documented here. Should you change them, please check
	 * the implementation of the various instructions to make sure
	 * that they still work.
	 *
	 * args->eh	The MAC header. It is non-null for a layer2
	 *	packet, it is NULL for a layer-3 packet.
	 * **notyet**
	 * args->L3offset Offset in the packet to the L3 (IP or equiv.) header.
	 *
	 * m | args->m	Pointer to the mbuf, as received from the caller.
	 *	It may change if ipfw_chk() does an m_pullup, or if it
	 *	consumes the packet because it calls send_reject().
	 *	XXX This has to change, so that ipfw_chk() never modifies
	 *	or consumes the buffer.
	 * ip	is the beginning of the ip(4 or 6) header.
	 *	Calculated by adding the L3offset to the start of data.
	 *	(Until we start using L3offset, the packet is
	 *	supposed to start with the ip header).
	 */
	struct ip *ip = mtod(m, struct ip *);

	/*
	 * For rules which contain uid/gid or jail constraints, cache
	 * a copy of the users credentials after the pcb lookup has been
	 * executed. This will speed up the processing of rules with
	 * these types of constraints, as well as decrease contention
	 * on pcb related locks.
	 */
#ifndef __FreeBSD__
	struct bsd_ucred ucred_cache;
#else
	struct ucred *ucred_cache = NULL;
#endif
	int ucred_lookup = 0;

	/*
	 * oif | args->oif	If NULL, ipfw_chk has been called on the
	 *	inbound path (ether_input, ip_input).
	 *	If non-NULL, ipfw_chk has been called on the outbound path
	 *	(ether_output, ip_output).
	 */
	struct ifnet *oif = args->oif;

	int f_pos = 0;		/* index of current rule in the array */
	int retval = 0;

	/*
	 * hlen	The length of the IP header.
	 */
	u_int hlen = 0;		/* hlen >0 means we have an IP pkt */

	/*
	 * offset	The offset of a fragment. offset != 0 means that
	 *	we have a fragment at this offset of an IPv4 packet.
	 *	offset == 0 means that (if this is an IPv4 packet)
	 *	this is the first or only fragment.
	 *	For IPv6 offset|ip6f_mf == 0 means there is no Fragment Header
	 *	or there is a single packet fragement (fragement header added
	 *	without needed).  We will treat a single packet fragment as if
	 *	there was no fragment header (or log/block depending on the
	 *	V_fw_permit_single_frag6 sysctl setting).
	 */
	u_short offset = 0;
	u_short ip6f_mf = 0;

	/*
	 * Local copies of addresses. They are only valid if we have
	 * an IP packet.
	 *
	 * proto	The protocol. Set to 0 for non-ip packets,
	 *	or to the protocol read from the packet otherwise.
	 *	proto != 0 means that we have an IPv4 packet.
	 *
	 * src_port, dst_port	port numbers, in HOST format. Only
	 *	valid for TCP and UDP packets.
	 *
	 * src_ip, dst_ip	ip addresses, in NETWORK format.
	 *	Only valid for IPv4 packets.
	 */
	uint8_t proto;
	uint16_t src_port = 0, dst_port = 0;	/* NOTE: host format	*/
	struct in_addr src_ip, dst_ip;		/* NOTE: network format	*/
	uint16_t iplen=0;
	int pktlen;
	uint16_t	etype = 0;	/* Host order stored ether type */

	/*
	 * dyn_dir = MATCH_UNKNOWN when rules unchecked,
	 * 	MATCH_NONE when checked and not matched (q = NULL),
	 *	MATCH_FORWARD or MATCH_REVERSE otherwise (q != NULL)
	 */
	int dyn_dir = MATCH_UNKNOWN;
	ipfw_dyn_rule *q = NULL;

	/*
	 * We store in ulp a pointer to the upper layer protocol header.
	 * In the ipv4 case this is easy to determine from the header,
	 * but for ipv6 we might have some additional headers in the middle.
	 * ulp is NULL if not found.
	 */
	void *ulp = NULL;		/* upper layer protocol pointer. */

	/* XXX ipv6 variables */
	int is_ipv6 = 0;
	uint8_t	icmp6_type = 0;
	uint16_t ext_hd = 0;	/* bits vector for extension header filtering */
	/* end of ipv6 variables */

	int is_ipv4 = 0;

	int done = 0;		/* flag to exit the outer loop */

	dst_ip.s_addr = 0;		/* make sure it is initialized */
	src_ip.s_addr = 0;		/* make sure it is initialized */
	pktlen = m->m_pkthdr.len;
	proto = args->f_id.proto = 0;	/* mark f_id invalid */
		/* XXX 0 is a valid proto: IP/IPv6 Hop-by-Hop Option */

	// Fill in some variables.
	inspect_pkt(args, ip, m, &src_ip, &dst_ip, &src_port, &dst_port, &etype, &ext_hd, &iplen, &pktlen, &is_ipv4, &is_ipv6, &hlen, &proto, &icmp6_type, &ip6f_mf, &offset, &ulp);

	IPFW_PF_RLOCK(chain);
	if (! V_ipfw_vnet_ready) { /* shutting down, leave NOW. */
		IPFW_PF_RUNLOCK(chain);
		return (IP_FW_PASS);	/* accept */
	}
	if (args->rule.slot) {
		/*
		 * Packet has already been tagged as a result of a previous
		 * match on rule args->rule aka args->rule_id (PIPE, QUEUE,
		 * REASS, NETGRAPH, DIVERT/TEE...)
		 * Validate the slot and continue from the next one
		 * if still present, otherwise do a lookup.
		 */
		f_pos = (args->rule.chain_id == chain->id) ?
		    args->rule.slot :
		    ipfw_find_rule(chain, args->rule.rulenum,
			args->rule.rule_id);
	} else {
		f_pos = 0;
	}

	/*
	 * Now scan the rules, and parse microinstructions for each rule.
	 * We have two nested loops and an inner switch. Sometimes we
	 * need to break out of one or both loops, or re-enter one of
	 * the loops with updated variables. Loop variables are:
	 *
	 *	f_pos (outer loop) points to the current rule.
	 *		On output it points to the matching rule.
	 *	done (outer loop) is used as a flag to break the loop.
	 *	l (inner loop)	residual length of current rule.
	 *		cmd points to the current microinstruction.
	 *
	 * We break the inner loop by setting l=0 and possibly
	 * cmdlen=0 if we don't want to advance cmd.
	 * We break the outer loop by setting done=1
	 * We can restart the inner loop by setting l>0 and f_pos, f, cmd
	 * as needed.
	 */
	for (; f_pos < chain->n_rules; f_pos++) {
		ipfw_insn *cmd;
		uint32_t tablearg = 0;
		int l, cmdlen, skip_or; /* skip rest of OR block */
		struct ip_fw *f;

		f = chain->map[f_pos];
		if (V_set_disable & (1 << f->set) )
			continue;

		skip_or = 0;
		for (l = f->cmd_len, cmd = f->cmd ; l > 0 ;
		    l -= cmdlen, cmd += cmdlen) {
			int match;

			/*
			 * check_body is a jump target used when we find a
			 * CHECK_STATE, and need to jump to the body of
			 * the target rule.
			 */

/* check_body: */
			cmdlen = F_LEN(cmd);
			/*
			 * An OR block (insn_1 || .. || insn_n) has the
			 * F_OR bit set in all but the last instruction.
			 * The first match will set "skip_or", and cause
			 * the following instructions to be skipped until
			 * past the one with the F_OR bit clear.
			 */
			if (skip_or) {		/* skip this instruction */
				if ((cmd->len & F_OR) == 0)
					skip_or = 0;	/* next one is good */
				continue;
			}
			match = 0; /* set to 1 if we succeed */

			switch (cmd->opcode) {
			/*
			 * The first set of opcodes compares the packet's
			 * fields with some pattern, setting 'match' if a
			 * match is found. At the end of the loop there is
			 * logic to deal with F_NOT and F_OR flags associated
			 * with the opcode.
			 */
			case O_NOP:
				rule_nop(&match);
				break;

			case O_FORWARD_MAC:
				rule_forward_mac(cmd->opcode);
				break;

			case O_GID:
			case O_UID:
			case O_JAIL:
				rule_jail(&match, offset, proto, cmd, args, ucred_lookup, ucred_cache);
				break;

			case O_RECV:
				rule_recv(&match, cmd, m, chain, &tablearg);
				break;

			case O_XMIT:
				rule_xmit(&match, oif, cmd, chain, &tablearg);
				break;

			case O_VIA:
				rule_via(&match, oif, m, cmd, chain, &tablearg);
				break;

			case O_MACADDR2:
				rule_macaddr2(&match, args, cmd);
				break;

			case O_MAC_TYPE:
				rule_mac_type(&match, args, cmd, cmdlen, etype);
				break;

			case O_FRAG:
				rule_frag(&match, offset);
				break;

			case O_IN:
				rule_in(&match, oif);
				break;

			case O_LAYER2:
				rule_layer2(&match, args);
				break;

			case O_DIVERTED:
				rule_diverted(&match, args, cmd);
				break;

			case O_PROTO:
				rule_proto(&match, proto, cmd);
				break;

			case O_IP_SRC:
				rule_ip_src(&match, is_ipv4, cmd, &src_ip);
				break;

			case O_IP_SRC_LOOKUP:
			case O_IP_DST_LOOKUP:
				rule_ip_dst_lookup(&match, cmd, cmdlen, args, &tablearg, is_ipv4, is_ipv6, ip, &dst_ip, &src_ip, dst_port, src_port, offset, proto, ucred_lookup, ucred_cache, chain);
				break;

			case O_IP_SRC_MASK:
			case O_IP_DST_MASK:
				rule_ip_dst_mask(&match, is_ipv4, cmd, cmdlen, &dst_ip, &src_ip);
				break;

			case O_IP_SRC_ME:
				rule_ip_src_me(&match, is_ipv4, is_ipv6, &src_ip, args);
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_SRC_ME:
				rule_ip6_src_me(&match, is_ipv6, args);
#endif
				break;

			case O_IP_DST_SET:
			case O_IP_SRC_SET:
				rule_ip_src_set(&match, is_ipv4, cmd, args);
				break;

			case O_IP_DST:
				rule_ip_dst(&match, is_ipv4, cmd, &dst_ip);
				break;

			case O_IP_DST_ME:
				rule_ip_dst_me(&match, args, is_ipv4, is_ipv6, &dst_ip);
				
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_DST_ME:
				rule_ip6_dst_me(&match, args, is_ipv6);
#endif
				break;


			case O_IP_SRCPORT:
			case O_IP_DSTPORT:
				rule_ip_dstport(&match, proto, offset, cmd, cmdlen, dst_port, src_port);
				break;

			case O_ICMPTYPE:
				rule_icmptype(&match, offset, proto, ulp, cmd);
				break;

#ifdef INET6
			case O_ICMP6TYPE:
				rule_icmp6type(&match, offset, is_ipv6, proto, ulp, cmd);
				break;
#endif /* INET6 */

			case O_IPOPT:
				rule_ipopt(&match, is_ipv4, ip, cmd);
				break;

			case O_IPVER:
				rule_ipver(&match, is_ipv4, cmd, ip);
				break;

			case O_IPID:
			case O_IPLEN:
			case O_IPTTL:
				rule_ipttl(&match, is_ipv4, cmd, cmdlen, ip, iplen);
				break;

			case O_IPPRECEDENCE:
				rule_ipprecedence(&match, is_ipv4, cmd, ip);
				break;

			case O_IPTOS:
				rule_iptos(&match, is_ipv4, cmd, ip);
				break;

			case O_DSCP:
				rule_dscp(&match, is_ipv4, is_ipv6, cmd, ip);
				break;

			case O_TCPDATALEN:
				rule_tcpdatalen(&match, proto, offset, ulp, iplen, cmdlen, cmd, ip);
				break;

			case O_TCPFLAGS:
				rule_tcpflags(&match, proto, offset, cmd, ulp);
				break;

			case O_TCPOPTS:
				if (rule_tcpopts(&match, hlen, ulp, proto, offset, cmd, m, args))
					goto pullup_failed;
				break;

			case O_TCPSEQ:
				rule_tcpseq(&match, proto, offset, cmd, ulp);
				break;

			case O_TCPACK:
				rule_tcpack(&match, proto, offset, cmd, ulp);
				break;

			case O_TCPWIN:
				rule_tcpwin(&match, proto, offset, cmd, cmdlen, ulp);
				break;

			case O_ESTAB:
				rule_estab(&match, proto, offset, ulp);
				break;

			case O_ALTQ:
				rule_altq(&match, cmd, m, ip);
				break;

			case O_LOG:
				rule_log(&match, f, hlen, args, m, oif, offset, ip6f_mf, tablearg, ip);
				break;

			case O_PROB:
				rule_prob(&match, cmd);
				break;

			case O_VERREVPATH:
				rule_verrevpath(&match, oif, m, is_ipv6, args, &src_ip);
				break;

			case O_VERSRCREACH:
				rule_versrcreach(&match, hlen, oif, is_ipv6, args, &src_ip);
				break;

			case O_ANTISPOOF:
				rule_antispoof(&match, oif, hlen, is_ipv4, is_ipv6, &src_ip, args, m);
				break;

			case O_IPSEC:
#ifdef IPSEC
				rule_ipsec(&match, m);
#endif
				/* otherwise no match */
				break;

#ifdef INET6
			case O_IP6_SRC:
				rule_ip6_src(&match, is_ipv6, args, cmd);
				break;

			case O_IP6_DST:
				rule_ip6_dst(&match, is_ipv6, args, cmd);
				break;

			case O_IP6_SRC_MASK:
			case O_IP6_DST_MASK:
				rule_ip6_dst_mask(&match, args, cmd, cmdlen, is_ipv6);
				break;

			case O_FLOW6ID:
				rule_flow6id(&match, is_ipv6, args, cmd);
				break;

			case O_EXT_HDR:
				rule_ext_hdr(&match, is_ipv6, ext_hd, cmd);
				break;

			case O_IP6:
				rule_ip6(&match, is_ipv6);
				break;
#endif

			case O_IP4:
				rule_ip4(&match, is_ipv4);
				break;

			case O_TAG: 
				rule_tag(&match, cmd, m, tablearg);
				break;

			case O_FIB: /* try match the specified fib */
				rule_fib(&match, args, cmd);
				break;

			case O_SOCKARG:
				rule_sockarg(&match, is_ipv6, proto, &dst_ip, &src_ip, dst_port, src_port, args, &tablearg);
				break;

			case O_TAGGED:
				rule_tagged(&match, cmd, cmdlen, m, tablearg);
				break;
				
			/*
			 * The second set of opcodes represents 'actions',
			 * i.e. the terminal part of a rule once the packet
			 * matches all previous patterns.
			 * Typically there is only one action for each rule,
			 * and the opcode is stored at the end of the rule
			 * (but there are exceptions -- see below).
			 *
			 * In general, here we set retval and terminate the
			 * outer loop (would be a 'break 3' in some language,
			 * but we need to set l=0, done=1)
			 *
			 * Exceptions:
			 * O_COUNT and O_SKIPTO actions:
			 *   instead of terminating, we jump to the next rule
			 *   (setting l=0), or to the SKIPTO target (setting
			 *   f/f_len, cmd and l as needed), respectively.
			 *
			 * O_TAG, O_LOG and O_ALTQ action parameters:
			 *   perform some action and set match = 1;
			 *
			 * O_LIMIT and O_KEEP_STATE: these opcodes are
			 *   not real 'actions', and are stored right
			 *   before the 'action' part of the rule.
			 *   These opcodes try to install an entry in the
			 *   state tables; if successful, we continue with
			 *   the next opcode (match=1; break;), otherwise
			 *   the packet must be dropped (set retval,
			 *   break loops with l=0, done=1)
			 *
			 * O_PROBE_STATE and O_CHECK_STATE: these opcodes
			 *   cause a lookup of the state table, and a jump
			 *   to the 'action' part of the parent rule
			 *   if an entry is found, or
			 *   (CHECK_STATE only) a jump to the next rule if
			 *   the entry is not found.
			 *   The result of the lookup is cached so that
			 *   further instances of these opcodes become NOPs.
			 *   The jump to the next rule is done by setting
			 *   l=0, cmdlen=0.
			 */
			case O_LIMIT:
			case O_KEEP_STATE:
				rule_keep_state(&match, f, cmd, args, tablearg, &retval, &l, &done);
				break;

			case O_PROBE_STATE:
			case O_CHECK_STATE:
				rule_check_state(&match, &dyn_dir, q, args, proto, ulp, pktlen, f, &f_pos, chain, cmd, &cmdlen, &l);
				break;

			case O_ACCEPT:
				rule_accept(&retval, &l, &done);
				break;

			case O_PIPE:
			case O_QUEUE:
				rule_queue(args, f_pos, chain, cmd, tablearg, &retval, &l, &done);
				break;

			case O_DIVERT:
			case O_TEE:
				rule_tee(&l, &done, &retval, cmd, args, f_pos, tablearg, chain);
				break;

			case O_COUNT:
				rule_count(&l, f, pktlen);
				break;

			case O_SKIPTO:
				rule_skipto(&match, &l, cmd, &cmdlen, &skip_or, &f_pos, f, pktlen, chain, tablearg);
			    continue;
			    break;	/* NOTREACHED */

			case O_CALLRETURN:
				rule_callreturn(cmd, m, f, chain, tablearg, pktlen, &skip_or, &cmdlen, &f_pos, &l);
				continue;
				break;	/* NOTREACHED */

			case O_REJECT:
				rule_reject(hlen, is_ipv4, offset, proto, ulp, m, &dst_ip, args, cmd, iplen, ip);
				/* FALLTHROUGH */
#ifdef INET6
			case O_UNREACH6:
				rule_unreach6(hlen, is_ipv6, offset, proto, icmp6_type, m, args, cmd, ip);
				/* FALLTHROUGH */
#endif
			case O_DENY:
				rule_deny(&l, &done, &retval);
				break;

			case O_FORWARD_IP:
				rule_forward_ip(args, q, f, dyn_dir, cmd, tablearg, &retval, &l, &done);
				break;

#ifdef INET6
			case O_FORWARD_IP6:
				rule_forward_ip6(args, q, f, dyn_dir, cmd, &retval, &l, &done);
				break;
#endif

			case O_NETGRAPH:
			case O_NGTEE:
				rule_ngtee(args, f_pos, chain, cmd, tablearg, &retval, &l, &done);
				break;

			case O_SETFIB:
				rule_setfib(f, pktlen, tablearg, cmd, m, args, &l);
				break;

			case O_SETDSCP:
				rule_setdscp(cmd, ip, is_ipv4, is_ipv6, tablearg, f, pktlen, &l);
				break;

			case O_NAT:
				rule_nat(args, f_pos, chain, cmd, m, tablearg, &retval, &done, &l);
				break;

			case O_REASS:
				rule_reass(f, f_pos, chain, pktlen, ip, args, m, &retval, &done, &l);
				break;

			default:
				panic("-- unknown opcode %d\n", cmd->opcode);
			} /* end of switch() on opcodes */
			/*
			 * if we get here with l=0, then match is irrelevant.
			 */

			if (cmd->len & F_NOT)
				match = !match;

			if (match) {
				if (cmd->len & F_OR)
					skip_or = 1;
			} else {
				if (!(cmd->len & F_OR)) /* not an OR block, */
					break;		/* try next rule    */
			}

		}	/* end of inner loop, scan opcodes */

		if (done)
			break;

/* next_rule:; */	/* try next rule		*/

	}		/* end of outer for, scan rules */

	if (done) {
		struct ip_fw *rule = chain->map[f_pos];
		/* Update statistics */
		IPFW_INC_RULE_COUNTER(rule, pktlen);
	} else {
		retval = IP_FW_DENY;
		printf("ipfw: ouch!, skip past end of rules, denying packet\n");
	}
	IPFW_PF_RUNLOCK(chain);
#if defined(__FreeBSD__) && !defined(USERSPACE)
	if (ucred_cache != NULL)
		crfree(ucred_cache);
#endif
	return (retval);

pullup_failed:
	if (V_fw_verbose)
		printf("ipfw: pullup failed\n");
	return (IP_FW_DENY);
}

/*
 * Set maximum number of tables that can be used in given VNET ipfw instance.
 */
#ifdef SYSCTL_NODE
static int
sysctl_ipfw_table_num(SYSCTL_HANDLER_ARGS)
{
	int error;
	unsigned int ntables;

	ntables = V_fw_tables_max;

	error = sysctl_handle_int(oidp, &ntables, 0, req);
	/* Read operation or some error */
	if ((error != 0) || (req->newptr == NULL))
		return (error);

	return (ipfw_resize_tables(&V_layer3_chain, ntables));
}
#endif
/*
 * Module and VNET glue
 */

/*
 * Stuff that must be initialised only on boot or module load
 */
static int
ipfw_init(void)
{
	int error = 0;

	/*
 	 * Only print out this stuff the first time around,
	 * when called from the sysinit code.
	 */
	printf("ipfw2 "
#ifdef INET6
		"(+ipv6) "
#endif
		"initialized, divert %s, nat %s, "
		"default to %s, logging ",
#ifdef IPDIVERT
		"enabled",
#else
		"loadable",
#endif
#ifdef IPFIREWALL_NAT
		"enabled",
#else
		"loadable",
#endif
		default_to_accept ? "accept" : "deny");

	/*
	 * Note: V_xxx variables can be accessed here but the vnet specific
	 * initializer may not have been called yet for the VIMAGE case.
	 * Tuneables will have been processed. We will print out values for
	 * the default vnet. 
	 * XXX This should all be rationalized AFTER 8.0
	 */
	if (V_fw_verbose == 0)
		printf("disabled\n");
	else if (V_verbose_limit == 0)
		printf("unlimited\n");
	else
		printf("limited to %d packets/entry by default\n",
		    V_verbose_limit);

	/* Check user-supplied table count for validness */
	if (default_fw_tables > IPFW_TABLES_MAX)
	  default_fw_tables = IPFW_TABLES_MAX;

	ipfw_log_bpf(1); /* init */

	return (error);
}

/*
 * Called for the removal of the last instance only on module unload.
 */
static void
ipfw_destroy(void)
{

	ipfw_log_bpf(0); /* uninit */
	printf("IP firewall unloaded\n");
}

/*
 * Stuff that must be initialized for every instance
 * (including the first of course).
 */
static int
vnet_ipfw_init(const void *unused)
{
	int error;
	struct ip_fw *rule = NULL;
	struct ip_fw_chain *chain;

	chain = &V_layer3_chain;

	/* First set up some values that are compile time options */
	V_autoinc_step = 100;	/* bounded to 1..1000 in add_rule() */
	V_fw_deny_unknown_exthdrs = 1;
#ifdef IPFIREWALL_VERBOSE
	V_fw_verbose = 1;
#endif
#ifdef IPFIREWALL_VERBOSE_LIMIT
	V_verbose_limit = IPFIREWALL_VERBOSE_LIMIT;
#endif
#ifdef IPFIREWALL_NAT
	LIST_INIT(&chain->nat);
#endif

	/* insert the default rule and create the initial map */
	chain->n_rules = 1;
	chain->static_len = sizeof(struct ip_fw);
	chain->map = malloc(sizeof(struct ip_fw *), M_IPFW, M_WAITOK | M_ZERO);
	if (chain->map)
		rule = malloc(chain->static_len, M_IPFW, M_WAITOK | M_ZERO);

	/* Set initial number of tables */
	V_fw_tables_max = default_fw_tables;
	error = ipfw_init_tables(chain);
	if (error) {
		printf("ipfw2: setting up tables failed\n");
		free(chain->map, M_IPFW);
		free(rule, M_IPFW);
		return (ENOSPC);
	}

	/* fill and insert the default rule */
	rule->act_ofs = 0;
	rule->rulenum = IPFW_DEFAULT_RULE;
	rule->cmd_len = 1;
	rule->set = RESVD_SET;
	rule->cmd[0].len = 1;
	rule->cmd[0].opcode = default_to_accept ? O_ACCEPT : O_DENY;
	chain->rules = chain->default_rule = chain->map[0] = rule;
	chain->id = rule->id = 1;

	IPFW_LOCK_INIT(chain);
	ipfw_dyn_init(chain);

	/* First set up some values that are compile time options */
	V_ipfw_vnet_ready = 1;		/* Open for business */

	/*
	 * Hook the sockopt handler and pfil hooks for ipv4 and ipv6.
	 * Even if the latter two fail we still keep the module alive
	 * because the sockopt and layer2 paths are still useful.
	 * ipfw[6]_hook return 0 on success, ENOENT on failure,
	 * so we can ignore the exact return value and just set a flag.
	 *
	 * Note that V_fw[6]_enable are manipulated by a SYSCTL_PROC so
	 * changes in the underlying (per-vnet) variables trigger
	 * immediate hook()/unhook() calls.
	 * In layer2 we have the same behaviour, except that V_ether_ipfw
	 * is checked on each packet because there are no pfil hooks.
	 */
	V_ip_fw_ctl_ptr = ipfw_ctl;
	error = ipfw_attach_hooks(1);
	return (error);
}

/*
 * Called for the removal of each instance.
 */
static int
vnet_ipfw_uninit(const void *unused)
{
	struct ip_fw *reap, *rule;
	struct ip_fw_chain *chain = &V_layer3_chain;
	int i;

	V_ipfw_vnet_ready = 0; /* tell new callers to go away */
	/*
	 * disconnect from ipv4, ipv6, layer2 and sockopt.
	 * Then grab, release and grab again the WLOCK so we make
	 * sure the update is propagated and nobody will be in.
	 */
	(void)ipfw_attach_hooks(0 /* detach */);
	V_ip_fw_ctl_ptr = NULL;
	IPFW_UH_WLOCK(chain);
	IPFW_UH_WUNLOCK(chain);
	IPFW_UH_WLOCK(chain);

	IPFW_WLOCK(chain);
	ipfw_dyn_uninit(0);	/* run the callout_drain */
	IPFW_WUNLOCK(chain);

	ipfw_destroy_tables(chain);
	reap = NULL;
	IPFW_WLOCK(chain);
	for (i = 0; i < chain->n_rules; i++) {
		rule = chain->map[i];
		rule->x_next = reap;
		reap = rule;
	}
	if (chain->map)
		free(chain->map, M_IPFW);
	IPFW_WUNLOCK(chain);
	IPFW_UH_WUNLOCK(chain);
	if (reap != NULL)
		ipfw_reap_rules(reap);
	IPFW_LOCK_DESTROY(chain);
	ipfw_dyn_uninit(1);	/* free the remaining parts */
	return 0;
}

/*
 * Module event handler.
 * In general we have the choice of handling most of these events by the
 * event handler or by the (VNET_)SYS(UN)INIT handlers. I have chosen to
 * use the SYSINIT handlers as they are more capable of expressing the
 * flow of control during module and vnet operations, so this is just
 * a skeleton. Note there is no SYSINIT equivalent of the module
 * SHUTDOWN handler, but we don't have anything to do in that case anyhow.
 */
static int
ipfw_modevent(module_t mod, int type, void *unused)
{
	int err = 0;

	switch (type) {
	case MOD_LOAD:
		/* Called once at module load or
	 	 * system boot if compiled in. */
		break;
	case MOD_QUIESCE:
		/* Called before unload. May veto unloading. */
		break;
	case MOD_UNLOAD:
		/* Called during unload. */
		break;
	case MOD_SHUTDOWN:
		/* Called during system shutdown. */
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ipfwmod = {
	"ipfw",
	ipfw_modevent,
	0
};

/* Define startup order. */
#define	IPFW_SI_SUB_FIREWALL	SI_SUB_PROTO_IFATTACHDOMAIN
#define	IPFW_MODEVENT_ORDER	(SI_ORDER_ANY - 255) /* On boot slot in here. */
#define	IPFW_MODULE_ORDER	(IPFW_MODEVENT_ORDER + 1) /* A little later. */
#define	IPFW_VNET_ORDER		(IPFW_MODEVENT_ORDER + 2) /* Later still. */

DECLARE_MODULE(ipfw, ipfwmod, IPFW_SI_SUB_FIREWALL, IPFW_MODEVENT_ORDER);
MODULE_VERSION(ipfw, 2);
/* should declare some dependencies here */

/*
 * Starting up. Done in order after ipfwmod() has been called.
 * VNET_SYSINIT is also called for each existing vnet and each new vnet.
 */
SYSINIT(ipfw_init, IPFW_SI_SUB_FIREWALL, IPFW_MODULE_ORDER,
	    ipfw_init, NULL);
VNET_SYSINIT(vnet_ipfw_init, IPFW_SI_SUB_FIREWALL, IPFW_VNET_ORDER,
	    vnet_ipfw_init, NULL);
 
/*
 * Closing up shop. These are done in REVERSE ORDER, but still
 * after ipfwmod() has been called. Not called on reboot.
 * VNET_SYSUNINIT is also called for each exiting vnet as it exits.
 * or when the module is unloaded.
 */
SYSUNINIT(ipfw_destroy, IPFW_SI_SUB_FIREWALL, IPFW_MODULE_ORDER,
	    ipfw_destroy, NULL);
VNET_SYSUNINIT(vnet_ipfw_uninit, IPFW_SI_SUB_FIREWALL, IPFW_VNET_ORDER,
	    vnet_ipfw_uninit, NULL);
/* end of file */
