#include <sys/param.h>
#include <sys/ucred.h>
#include <netinet/in.h>

// #define IPFW_RULES_INLINE __unused
#define IPFW_RULES_INLINE __attribute__((used)) __always_inline
#include "ip_fw_rules.h"

// The real function will be compiled and inserted by the JIT.
int ipfw_chk_jit(struct ip_fw_args *args, struct ip_fw_chain *chain);
static int jump_fast(struct ip_fw_chain *chain, struct ip_fw *f, int num,
					int tablearg, int jump_backwards);
static void set_match(struct ip_fw_args *args, int slot, struct ip_fw_chain *chain);
static int is_icmp_query(struct icmphdr *icmp);
static int ipopts_match(struct ip *ip, ipfw_insn *cmd);
static int tcpopts_match(struct tcphdr *tcp, ipfw_insn *cmd);
static int iface_match(struct ifnet *ifp, ipfw_insn_if *cmd, 
				struct ip_fw_chain *chain, uint32_t *tablearg);
static int verify_path(struct in_addr src, struct ifnet *ifp, u_int fib);
static void send_reject(struct ip_fw_args *args, int code, int iplen, 
						struct ip *ip);

time_t time_uptime = 0;

/* XXX Function defined at ip_fw_sockopt.c
 * Find the smallest rule >= key, id.
 * We could use bsearch but it is so simple that we code it directly
 */
int
ipfw_find_rule(struct ip_fw_chain *chain, uint32_t key, uint32_t id)
{
	int i, lo, hi;
	struct ip_fw *r;

  	for (lo = 0, hi = chain->n_rules - 1; lo < hi;) {
		i = (lo + hi) / 2;
		r = chain->map[i];
		if (r->rulenum < key)
			lo = i + 1;	/* continue from the next one */
		else if (r->rulenum > key)
			hi = i;		/* this might be good */
		else if (r->id < id)
			lo = i + 1;	/* continue from the next one */
		else /* r->id >= id */
			hi = i;		/* this might be good */
	};
	return hi;
}

/* Defined at extra/missing.c */
struct tags_freelist tags_freelist;
int tags_minlen = 64;
int tags_freelist_count = 0;
static int tags_freelist_max = 0;
struct mbuf *mbuf_freelist;
#ifdef __FreeBSD__
       struct bsd_ucred ucred_cache;
#else
       struct ucred ucred_cache;
#endif


void
m_freem(struct mbuf *m)
{
	struct m_tag *t;

	/* free the m_tag chain */
	while ( (t = SLIST_FIRST(&m->m_pkthdr.tags) ) ) {
		ND("free tag %p", &m->m_pkthdr.tags);
		SLIST_REMOVE_HEAD(&m->m_pkthdr.tags, m_tag_link);
		SLIST_INSERT_HEAD(&tags_freelist, t, m_tag_link);
		tags_freelist_count++;
		if (tags_freelist_count > tags_freelist_max) {
			static int pr=0;
			if ((pr++ % 1000) == 0)
				D("new max %d", tags_freelist_count);
			tags_freelist_max = tags_freelist_count;
		}
	}
	if (m->m_flags & M_STACK) {
		ND("free invalid mbuf %p", m);
		return;
	}
	/* free the mbuf */
	ND("free(m = %p, M_IPFW);", m);
	m->m_next = mbuf_freelist;
	mbuf_freelist = m;
};


// Declarations of some needed structs for JIT compilation.
struct mbuf;
struct ifnet;
struct in_addr;
struct ip;
struct ip_fw_args;
struct ip_fw_chain;
struct ip_fw;
struct _ipfw_insn;
struct _ipfw_insn_ip;
struct _ipfw_insn_u16;
struct _ipfw_insn_if;
struct _ipfw_dyn_rule;

// This functions only forces the compiler to store the stubs of the functions
// so that they can be used by the JIT-compiled code instead.
// This function is not to be called ever.
void
voidfunction()
{
	struct ip_fw_args arguments;
	struct ip_fw_chain chainss;

	// These structs are not included.
	// We need to do something with them.
	struct _ipfw_insn_if insnif;
	struct _ipfw_dyn_rule rules;
	struct _ipfw_insn_ip ip;
	struct _ipfw_insn_u16 u16;
	struct _ipfw_dyn_rule rule;
	struct ip_fw_args *args;
	struct ip_fw_chain *chain = &chainss;
	struct ip_fw f;
	struct icmphdr icmp;
	struct ip ipstruct;
	struct tcphdr tcp;
	ipfw_insn cmd;
	struct ifnet ifp;
	ipfw_insn_if cmdif;
	struct in_addr src;

	int n, tablearg, jmp;
	uint32_t t;
	u_int fib;

	args = &arguments;
	ip.o.opcode = 1;
	u16.o.opcode = 1;
	rule.pcnt = 0;

	ipfw_find_rule(chain, 0, 0);
	insnif.o.opcode = 0;
	rules.next = &rules;

	/* Functions */
	ipfw_chk_jit(args, chain);
	n = tablearg = jmp = t = fib = 0;
	jump_fast(chain, &f, n, tablearg, jmp);
	set_match(args, n, chain);
	is_icmp_query(&icmp);
	ipopts_match(&ipstruct, &cmd);
	tcpopts_match(&tcp, &cmd);
	iface_match(&ifp, &cmdif, chain, &t);
	verify_path(src, &ifp, fib);
	send_reject(args, tablearg , n, &ipstruct);
}

