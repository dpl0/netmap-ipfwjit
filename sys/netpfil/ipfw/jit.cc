#include <sys/mbuf.h>
#include <sys/types.h>

#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <netinet/in_pcb.h>
#include <netpfil/ipfw/dn_heap.h>
#include <netpfil/ipfw/ip_dn_private.h>
#include <netpfil/ipfw/ip_fw_private.h>

#include <glue.h>
#include <missing.h>
#include <err.h>

#include <llvmc/Core.h>
#include <llvmc/IRReader.h>

typedef int (*funcptr)();

//Vars used for compilation
LLVMModuleRef Mod;
LLVMContextRef Con;
LLVMBuilderRef Irb;
// This is the function we're working on.
LLVMValueRef Func;

// We'll store the BasicBlocks for each rule here.
int rulenumber = 0;
int nrules = 0;
LLVMBasicBlockRef *rules;

// Vars Types
LLVMTypeRef Int8Ty;
LLVMTypeRef Int16Ty;
LLVMTypeRef Int32Ty;
LLVMTypeRef Int64Ty;
PointerType *Int8PtrTy;
PointerType *Int16PtrTy;

// Basic blocks used
LLVMBasicBlockRef Entry;
LLVMBasicBlockRef End;
LLVMBasicBlockRef PullupFailed;
LLVMBasicBlockRef CheckTag;

// JIT Compiled Vars
// These are the function arguments.
LLVMValueRef Args;
LLVMValueRef Chain;
// Loop control vars.
LLVMValueRef Match;
LLVMValueRef L;
LLVMValueRef M;
LLVMValueRef Done;
LLVMValueRef FPos;
LLVMValueRef Retval;
LLVMValueRef Cmd;
LLVMValueRef Cmdlen;
LLVMValueRef Tablearg;
LLVMValueRef SkipOr;
LLVMValueRef F;

// Packet matching vars.
LLVMValueRef MPtr;
LLVMValueRef IpPtr;
LLVMValueRef Ucred_cache;
LLVMValueRef Ucred_lookup;
LLVMValueRef Oif;
LLVMValueRef Hlen; //unsigned
LLVMValueRef Offset; //unsigned
LLVMValueRef Ip6fMf; //unsigned

// Local copies of vars.
// On optimization, unused ones will not be included.
LLVMValueRef Proto; //unsigned
LLVMValueRef SrcPort; //unsigned
LLVMValueRef DstPort; //unsigned
LLVMValueRef SrcIp;
LLVMValueRef DstIp;
LLVMValueRef Iplen; //unsigned
LLVMValueRef Pktlen;
LLVMValueRef Etype; //unsigned
LLVMValueRef Dyn_dir;
LLVMValueRef Q;
LLVMValueRef Ulp;
LLVMValueRef IsIpv4;
LLVMValueRef IsIpv6;
LLVMValueRef Icmp6Type; //unsigned
LLVMValueRef ExtHd; //unsigned

// Functions
// This sets up some vars, at start time.
LLVMValueRef InspectPkt;

// Auxiliary functions used by our JITed code.
// All this are used from our bitcode.
LLVMValueRef IsIcmpQuery;
LLVMValueRef FlagsMatch;
LLVMValueRef IpoptsMatch;
LLVMValueRef TcpoptsMatch;
LLVMValueRef IfaceMatch;
LLVMValueRef VerifyPath;
#ifdef INET6
LLVMValueRef Icmp6typeMatch;
LLVMValueRef SearchIp6AddrNet;
LLVMValueRef Flow6idMatch;
LLVMValueRef VerifyPath6;
LLVMValueRef IsIcmp6Query;
LLVMValueRef SendReject6;
#endif /* INET6 */
LLVMValueRef SendReject;
LLVMValueRef SetMatch;
LLVMValueRef JumpFast;

// External funcs
LLVMValueRef PrintfFunc;
LLVMValueRef IpfwFindRule;

// Rule funcs
LLVMValueRef RuleNop;
LLVMValueRef RuleForwardMac;
LLVMValueRef RuleJail;
LLVMValueRef RuleRecv;
LLVMValueRef RuleXmit;
LLVMValueRef RuleVia;
LLVMValueRef RuleMacaddr2;
LLVMValueRef RuleMacType;
LLVMValueRef RuleFrag;
LLVMValueRef RuleIn;
LLVMValueRef RuleLayer2;
LLVMValueRef RuleDiverted;
LLVMValueRef RuleProto;
LLVMValueRef RuleIpSrc;
LLVMValueRef RuleIpDstLookup;
LLVMValueRef RuleIpDstMask;
LLVMValueRef RuleIpSrcMe;
#ifdef INET6
LLVMValueRef RuleIp6SrcMe;
#endif
LLVMValueRef RuleIpSrcSet;
LLVMValueRef RuleIpDst;
LLVMValueRef RuleIpDstMe;
#ifdef INET6
LLVMValueRef RuleIp6DstMe;
#endif
LLVMValueRef RuleIpDstport;
LLVMValueRef RuleIcmptype;
#ifdef INET6
LLVMValueRef RuleIcmp6type;
#endif
LLVMValueRef RuleIpopt;
LLVMValueRef RuleIpver;
LLVMValueRef RuleIpttl;
LLVMValueRef RuleIpprecedence;
LLVMValueRef RuleIptos;
LLVMValueRef RuleDscp;
LLVMValueRef RuleTcpdatalen;
LLVMValueRef RuleTcpflags;
LLVMValueRef RuleTcpopts;
LLVMValueRef RuleTcpseq;
LLVMValueRef RuleTcpack;
LLVMValueRef RuleTcpwin;
LLVMValueRef RuleEstab;
LLVMValueRef RuleAltq;
LLVMValueRef RuleLog;
LLVMValueRef RuleProb;
LLVMValueRef RuleVerrevpath;
LLVMValueRef RuleVersrcreach;
LLVMValueRef RuleAntispoof;
#ifdef IPSEC
LLVMValueRef RuleIpsec;
#endif
#ifdef INET6
LLVMValueRef RuleIp6Src;
LLVMValueRef RuleIp6Dst;
LLVMValueRef RuleIp6DstMask;
LLVMValueRef RuleFlow6id;
LLVMValueRef RuleExtHdr;
LLVMValueRef RuleIp6;
#endif
LLVMValueRef RuleIp4;
LLVMValueRef RuleTag;
LLVMValueRef RuleFib;
LLVMValueRef RuleSockarg;
LLVMValueRef RuleTagged;
LLVMValueRef RuleKeepState;
LLVMValueRef RuleCheckState;
LLVMValueRef RuleAccept;
LLVMValueRef RuleQueue;
LLVMValueRef RuleTee;
LLVMValueRef RuleCount;
LLVMValueRef RuleSkipto;
LLVMValueRef RuleCallreturn;
LLVMValueRef RuleReject;
#ifdef INET6
LLVMValueRef RuleUnreach6;
#endif
LLVMValueRef RuleDeny;
LLVMValueRef RuleForwardIp;
#ifdef INET6
LLVMValueRef RuleForwardIp6;
#endif
LLVMValueRef RuleNgtee;
LLVMValueRef RuleSetfib;
LLVMValueRef RuleSetdscp;
LLVMValueRef RuleNat;
LLVMValueRef RuleReass;

// Used structs.
LLVMValueRef IfnetTy;
LLVMValueRef In_addrTy;
LLVMValueRef IpTy;
LLVMValueRef Ip_fw_argsTy;
LLVMValueRef Ip_fw_chainTy;
LLVMValueRef Ip_fwTy;
LLVMValueRef Ipfw_insnTy;
LLVMValueRef IpfwInsnU16Ty;
LLVMValueRef IpfwInsnIpTy;
LLVMValueRef Ipfw_dyn_ruleTy;
LLVMValueRef Ipfw_insn_ifTy;
LLVMValueRef MbufTy;
LLVMValueRef UcredTy;

// Pointer to structs type.
LLVMValueRef IfnetPtrTy;
LLVMValueRef In_addrPtrTy;
LLVMValueRef IpPtrTy;
LLVMValueRef Ip_fw_argsPtrTy;
LLVMValueRef Ip_fw_chainPtrTy;
LLVMValueRef Ip_fwPtrTy;
LLVMValueRef Ipfw_insnPtrTy;
LLVMValueRef IpfwInsnU16PtrTy;
LLVMValueRef IpfwInsnIpPtrTy;
LLVMValueRef Ipfw_dyn_rulePtrTy;
LLVMValueRef Ipfw_insn_ifPtrTy;
LLVMValueRef MbufPtrTy;
LLVMValueRef UcredPtrTy;

// Load the bc for JIT compilation.
void
loadBitcode()
{
	LLVMBool res;
	LLVMMemoryBufferRef buf;
	char *msg;

	res = LLVMCreateMemoryBufferWithContentsOfFile("rules.bc", &buf, &msg);
	if (res != 0)
		printf("Error when getting the bitcode: %s\n", msg);
	res = LLVMParseIRInContext(Con, buf, &Mod, &msg);
	if (res != 0)
		printf("Error when parsing the bitcode: %s\n", msg);
}

LLVMBasicBlockRef *
nextRule()
{
	int nextn = rulenumber + 1;
	if (nextn > nrules)
		return (&End);
	else
		return (&rules[nextn]);
}

// Create the needed variables to perform pfil.
void
setEnv()
{
	// Get function arguments.
	// Error
	if (LLVMCountParams(Func) != 2)
		err(1, "Compilation error: no correct parameters\n");

	// (struct ip_fw_args *, struct ip_fw_chain *)
	Args = LLVMGetParams(Func, 0);
	Chain = LLVMGetParams(Func, 1);

	// Get Type objects
	Int8Ty = LLVMInt8TypeInContext(Con);
	Int16Ty = LLVMInt16TypeInContext(Con);
	Int32Ty = LLVMInt32TypeInContext(Con);
	Int64Ty = LLVMInt64TypeInContext(Con);

	Int8PtrTy = LLVMPointerType(Int8Ty, 0);
	Int16PtrTy = LLVMPointerType(Int16Ty, 0);

	// Get StrucType from bitcode.
	MbufTy = LLVMGetTypeByName(Mod, "struct.mbuf");
	if (MbufTy == NULL)
		err(1, "bitcode fault: struct.mbuf");
	IfnetTy = LLVMGetTypeByName(Mod, "struct.IfnetTy");
	if (IfnetTy == NULL)
		err(1, "bitcode fault: struct.ifnet");
	In_addrTy = LLVMGetTypeByName(Mod, "struct.in_addr");
	if (In_addrTy == NULL)
		err(1, "bitcode fault: struct.in_addr");
	IpTy = LLVMGetTypeByName(Mod, "struct.ip");
	if (IpTy == NULL)
		err(1, "bitcode fault: struct.ip");
	Ip_fw_argsTy = LLVMGetTypeByName(Mod, "struct.ip_fw_args");
	if (Ip_fw_argsTy == NULL)
		err(1, "bitcode fault: struct.ip_fw_args");
	Ip_fw_chainTy = LLVMGetTypeByName(Mod, "struct.ip_fw_chain");
	if (Ip_fw_chainTy == NULL)
		err(1, "bitcode fault: struct.ip_fw_chain");
	Ip_fwTy = LLVMGetTypeByName(Mod, "struct.ip_fw");
	if (Ip_fwTy == NULL)
		err(1, "bitcode fault: struct.ip_fw");
	Ipfw_insnTy = LLVMGetTypeByName(Mod, "struct._ipfw_insn");
	if (Ipfw_insnTy == NULL)
		err(1, "bitcode fault: struct._ipfw_insn");
	IpfwInsnU16Ty = LLVMGetTypeByName(Mod, "struct._ipfw_insn_u16");
	if (IpfwInsnU16Ty == NULL)
		err(1, "bitcode fault: struct._ipfw_insn_u16");
	IpfwInsnIpTy = LLVMGetTypeByName(Mod, "struct._ipfw_insn_ip");
	if (IpfwInsnIpTy == NULL)
		err(1, "bitcode fault: struct._ipfw_insn_ip");
	Ipfw_insn_ifTy = LLVMGetTypeByName(Mod, "struct._ipfw_insn_if");
	if (Ipfw_insn_ifTy == NULL)
		err(1, "bitcode fault: struct._ipfw_insn_if");
	Ipfw_dyn_ruleTy = LLVMGetTypeByName(Mod, "struct._ipfw_dyn_rule");
	if (Ipfw_dyn_ruleTy == NULL)
		err(1, "bitcode fault: struct._ipfw_dyn_rule");

	// Create Pointer to StructType types.
	MbufPtrTy = LLVMPointerType(MbufTy, 0);
	IfnetPtrTy = LLVMPointerType(IfnetTy, 0);
	In_addrPtrTy = LLVMPointerType(In_addrTy, 0);
	IpPtrTy = LLVMPointerType(IpTy, 0);
	Ip_fw_argsPtrTy = LLVMPointerType(Ip_fw_argsTy, 0);
	Ip_fw_chainPtrTy = LLVMPointerType(Ip_fw_chainTy, 0);
	Ip_fwPtrTy = LLVMPointerType(Ip_fwTy, 0);
	Ipfw_insnPtrTy = LLVMPointerType(Ipfw_insnTy, 0);
	IpfwInsnU16PtrTy = LLVMPointerType(IpfwInsnU16Ty, 0);
	IpfwInsnIpPtrTy = LLVMPointerType(IpfwInsnIpTy, 0);
	Ipfw_insn_ifPtrTy = LLVMPointerType(Ipfw_insn_ifTy, 0);
	Ipfw_dyn_rulePtrTy = LLVMPointerType(Ipfw_dyn_ruleTy, 0);

	// Get Function defs from bitcode.
	// All of them are auxiliary functions.
	InspectPkt = LLVMGetTypeByName(Mod, "inspect_pkt");
	if (InspectPkt == NULL)
		err(1, "bitcode fault: inspect_pkt");
	IsIcmpQuery = LLVMGetTypeByName(Mod, "is_icmp_query");
	if (IsIcmpQuery == NULL)
		err(1, "bitcode fault: is_icmp_query");
	FlagsMatch = LLVMGetTypeByName(Mod, "flags_match");
	if (FlagsMatch == NULL)
		err(1, "bitcode fault: flags_match");
	IpoptsMatch = LLVMGetTypeByName(Mod, "ipopts_match");
	if (IpoptsMatch == NULL)
		err(1, "bitcode fault: ipopts_match");
	TcpoptsMatch = LLVMGetTypeByName(Mod, "tcpopts_match");
	if (TcpoptsMatch == NULL)
		err(1, "bitcode fault: tcpopts_match");
	IfaceMatch = LLVMGetTypeByName(Mod, "iface_match");
	if (IfaceMatch == NULL)
		err(1, "bitcode fault: iface_match");
	VerifyPath = LLVMGetTypeByName(Mod, "verify_path");
	if (VerifyPath == NULL)
		err(1, "bitcode fault: verify_path");

#ifdef INET6
	Icmp6typeMatch = LLVMGetTypeByName(Mod, "icmp6type_match");
	if (Icmp6typeMatch == NULL)
		err(1, "bitcode fault: icmp6type_match");
	SearchIp6AddrNet = LLVMGetTypeByName(Mod, "search_ip6_addr_net");
	if (SearchIp6AddrNet == NULL)
		err(1, "bitcode fault: search_ip6_addr_net");
	Flow6idMatch = LLVMGetTypeByName(Mod, "flow6id_match");
	if (Flow6idMatch == NULL)
		err(1, "bitcode fault: flow6id_match");
	VerifyPath6 = LLVMGetTypeByName(Mod, "verify_path6");
	if (VerifyPath6 == NULL)
		err(1, "bitcode fault: verify_path6");
	IsIcmp6Query = LLVMGetTypeByName(Mod, "is_icmp6_query");
	if (IsIcmp6Query == NULL)
		err(1, "bitcode fault: is_icmp6_query");
	SendReject6 = LLVMGetTypeByName(Mod, "send_reject6");
	if (SendReject6 == NULL)
		err(1, "bitcode fault: send_reject6");
#endif /* INET6 */

	SendReject = LLVMGetTypeByName(Mod, "send_reject");
	if (SendReject == NULL)
		err(1, "bitcode fault: send_reject");
	SetMatch = LLVMGetTypeByName(Mod, "set_match");
	if (SetMatch == NULL)
		err(1, "bitcode fault: set_match");
	JumpFast = LLVMGetTypeByName(Mod, "jump_fast");
	if (JumpFast == NULL)
		err(1, "bitcode fault: jump_fast");

	// Functions declared at bitcode.
	PrintfFunc = LLVMGetTypeByName(Mod, "printf");
	if (PrintfFunc == NULL)
		err(1, "bitcode fault: printf");
	IpfwFindRule = LLVMGetTypeByName(Mod, "ipfw_find_rule");
	if (IpfwFindRule == NULL)
		err(1, "bitcode fault: ipfw_find_rule");

	// Load the rules
	RuleNop = LLVMGetTypeByName(Mod, "rule_nop");
	if (RuleNop  == NULL)
		err(1, "bitcode fault: RuleNop ");
	RuleForwardMac = LLVMGetTypeByName(Mod, "rule_forward_mac");
	if (RuleForwardMac  == NULL)
		err(1, "bitcode fault: RuleForwardMac ");
	RuleJail = LLVMGetTypeByName(Mod, "rule_jail");
	if (RuleJail  == NULL)
		err(1, "bitcode fault: RuleJail ");
	RuleRecv = LLVMGetTypeByName(Mod, "rule_recv");
	if (RuleRecv  == NULL)
		err(1, "bitcode fault: RuleRecv ");
	RuleXmit = LLVMGetTypeByName(Mod, "rule_xmit");
	if (RuleXmit  == NULL)
		err(1, "bitcode fault: RuleXmit ");
	RuleVia = LLVMGetTypeByName(Mod, "rule_via");
	if (RuleVia  == NULL)
		err(1, "bitcode fault: RuleVia ");
	RuleMacaddr2 = LLVMGetTypeByName(Mod, "rule_macaddr2");
	if (RuleMacaddr2  == NULL)
		err(1, "bitcode fault: RuleMacaddr2 ");
	RuleMacType = LLVMGetTypeByName(Mod, "rule_mac_type");
	if (RuleMacType  == NULL)
		err(1, "bitcode fault: RuleMacType ");
	RuleFrag = LLVMGetTypeByName(Mod, "rule_frag");
	if (RuleFrag  == NULL)
		err(1, "bitcode fault: RuleFrag ");
	RuleIn = LLVMGetTypeByName(Mod, "rule_in");
	if (RuleIn  == NULL)
		err(1, "bitcode fault: RuleIn ");
	RuleLayer2 = LLVMGetTypeByName(Mod, "rule_layer2");
	if (RuleLayer2  == NULL)
		err(1, "bitcode fault: RuleLayer2 ");
	RuleDiverted = LLVMGetTypeByName(Mod, "rule_diverted");
	if (RuleDiverted  == NULL)
		err(1, "bitcode fault: RuleDiverted ");
	RuleProto = LLVMGetTypeByName(Mod, "rule_proto");
	if (RuleProto  == NULL)
		err(1, "bitcode fault: RuleProto ");
	RuleIpSrc = LLVMGetTypeByName(Mod, "rule_ip_src");
	if (RuleIpSrc  == NULL)
		err(1, "bitcode fault: RuleIpSrc ");
	RuleIpDstLookup = LLVMGetTypeByName(Mod, "rule_ip_dst_lookup");
	if (RuleIpDstLookup  == NULL)
		err(1, "bitcode fault: RuleIpDstLookup ");
	RuleIpDstMask = LLVMGetTypeByName(Mod, "rule_ip_dst_mask");
	if (RuleIpDstMask  == NULL)
		err(1, "bitcode fault: RuleIpDstMask ");
	RuleIpSrcMe = LLVMGetTypeByName(Mod, "rule_ip_src_me");
	if (RuleIpSrcMe  == NULL)
		err(1, "bitcode fault: RuleIpSrcMe ");
#ifdef INET6
	RuleIp6SrcMe = LLVMGetTypeByName(Mod, "rule_ip6_src_me");
	if (RuleIp6SrcMe  == NULL)
		err(1, "bitcode fault: RuleIp6SrcMe ");
#endif
	RuleIpSrcSet = LLVMGetTypeByName(Mod, "rule_ip_src_set");
	if (RuleIpSrcSet  == NULL)
		err(1, "bitcode fault: RuleIpSrcSet ");
	RuleIpDst = LLVMGetTypeByName(Mod, "rule_ip_dst");
	if (RuleIpDst  == NULL)
		err(1, "bitcode fault: RuleIpDst ");
	RuleIpDstMe = LLVMGetTypeByName(Mod, "rule_ip_dst_me");
	if (RuleIpDstMe  == NULL)
		err(1, "bitcode fault: RuleIpDstMe ");
#ifdef INET6
	RuleIp6DstMe = LLVMGetTypeByName(Mod, "rule_ip6_dst_me");
	if (RuleIp6DstMe  == NULL)
		err(1, "bitcode fault: RuleIp6DstMe ");
#endif
	RuleIpDstport = LLVMGetTypeByName(Mod, "rule_ip_dstport");
	if (RuleIpDstport  == NULL)
		err(1, "bitcode fault: RuleIpDstport ");
	RuleIcmptype = LLVMGetTypeByName(Mod, "rule_icmptype");
	if (RuleIcmptype  == NULL)
		err(1, "bitcode fault: RuleIcmptype ");
#ifdef INET6
	RuleIcmp6type = LLVMGetTypeByName(Mod, "rule_icmp6type");
	if (RuleIcmp6type  == NULL)
		err(1, "bitcode fault: RuleIcmp6type ");
#endif
	RuleIpopt = LLVMGetTypeByName(Mod, "rule_ipopt");
	if (RuleIpopt  == NULL)
		err(1, "bitcode fault: RuleIpopt ");
	RuleIpver = LLVMGetTypeByName(Mod, "rule_ipver");
	if (RuleIpver  == NULL)
		err(1, "bitcode fault: RuleIpver ");
	RuleIpttl = LLVMGetTypeByName(Mod, "rule_ipttl");
	if (RuleIpttl  == NULL)
		err(1, "bitcode fault: RuleIpttl ");
	RuleIpprecedence = LLVMGetTypeByName(Mod, "rule_ipprecedence");
	if (RuleIpprecedence  == NULL)
		err(1, "bitcode fault: RuleIpprecedence ");
	RuleIptos = LLVMGetTypeByName(Mod, "rule_iptos");
	if (RuleIptos  == NULL)
		err(1, "bitcode fault: RuleIptos ");
	RuleDscp = LLVMGetTypeByName(Mod, "rule_dscp");
	if (RuleDscp  == NULL)
		err(1, "bitcode fault: RuleDscp ");
	RuleTcpdatalen = LLVMGetTypeByName(Mod, "rule_tcpdatalen");
	if (RuleTcpdatalen  == NULL)
		err(1, "bitcode fault: RuleTcpdatalen ");
	RuleTcpflags = LLVMGetTypeByName(Mod, "rule_tcpflags");
	if (RuleTcpflags  == NULL)
		err(1, "bitcode fault: RuleTcpflags ");
	RuleTcpopts = LLVMGetTypeByName(Mod, "rule_tcpopts");
	if (RuleTcpopts  == NULL)
		err(1, "bitcode fault: RuleTcpopts ");
	RuleTcpseq = LLVMGetTypeByName(Mod, "rule_tcpseq");
	if (RuleTcpseq  == NULL)
		err(1, "bitcode fault: RuleTcpseq ");
	RuleTcpack = LLVMGetTypeByName(Mod, "rule_tcpack");
	if (RuleTcpack  == NULL)
		err(1, "bitcode fault: RuleTcpack ");
	RuleTcpwin = LLVMGetTypeByName(Mod, "rule_tcpwin");
	if (RuleTcpwin  == NULL)
		err(1, "bitcode fault: RuleTcpwin ");
	RuleEstab = LLVMGetTypeByName(Mod, "rule_estab");
	if (RuleEstab  == NULL)
		err(1, "bitcode fault: RuleEstab ");
	RuleAltq = LLVMGetTypeByName(Mod, "rule_altq");
	if (RuleAltq  == NULL)
		err(1, "bitcode fault: RuleAltq ");
	RuleLog = LLVMGetTypeByName(Mod, "rule_log");
	if (RuleLog  == NULL)
		err(1, "bitcode fault: RuleLog ");
	RuleProb = LLVMGetTypeByName(Mod, "rule_prob");
	if (RuleProb  == NULL)
		err(1, "bitcode fault: RuleProb ");
	RuleVerrevpath = LLVMGetTypeByName(Mod, "rule_verrevpath");
	if (RuleVerrevpath  == NULL)
		err(1, "bitcode fault: RuleVerrevpath ");
	RuleVersrcreach = LLVMGetTypeByName(Mod, "rule_versrcreach");
	if (RuleVersrcreach  == NULL)
		err(1, "bitcode fault: RuleVersrcreach ");
	RuleAntispoof = LLVMGetTypeByName(Mod, "rule_antispoof");
	if (RuleAntispoof  == NULL)
		err(1, "bitcode fault: RuleAntispoof ");
#ifdef IPSEC
	RuleIpsec = LLVMGetTypeByName(Mod, "rule_ipsec");
	if (RuleIpsec  == NULL)
		err(1, "bitcode fault: RuleIpsec ");
#endif
#ifdef INET6
	RuleIp6Src = LLVMGetTypeByName(Mod, "rule_ip6_src");
	if (RuleIp6Src  == NULL)
		err(1, "bitcode fault: RuleIp6Src ");
	RuleIp6Dst = LLVMGetTypeByName(Mod, "rule_ip6_dst");
	if (RuleIp6Dst  == NULL)
		err(1, "bitcode fault: RuleIp6Dst ");
	RuleIp6DstMask = LLVMGetTypeByName(Mod, "rule_ip6_dst_mask");
	if (RuleIp6DstMask  == NULL)
		err(1, "bitcode fault: RuleIp6DstMask ");
	RuleFlow6id = LLVMGetTypeByName(Mod, "rule_flow6id");
	if (RuleFlow6id  == NULL)
		err(1, "bitcode fault: RuleFlow6id ");
	RuleExtHdr = LLVMGetTypeByName(Mod, "rule_ext_hdr");
	if (RuleExtHdr  == NULL)
		err(1, "bitcode fault: RuleExtHdr ");
	RuleIp6 = LLVMGetTypeByName(Mod, "rule_ip6");
	if (RuleIp6  == NULL)
		err(1, "bitcode fault: RuleIp6 ");
#endif
	RuleIp4 = LLVMGetTypeByName(Mod, "rule_ip4");
	if (RuleIp4  == NULL)
		err(1, "bitcode fault: RuleIp4 ");
	RuleTag = LLVMGetTypeByName(Mod, "rule_tag");
	if (RuleTag  == NULL)
		err(1, "bitcode fault: RuleTag ");
	RuleFib = LLVMGetTypeByName(Mod, "rule_fib");
	if (RuleFib  == NULL)
		err(1, "bitcode fault: RuleFib ");
	RuleSockarg = LLVMGetTypeByName(Mod, "rule_sockarg");
	if (RuleSockarg  == NULL)
		err(1, "bitcode fault: RuleSockarg ");
	RuleTagged = LLVMGetTypeByName(Mod, "rule_tagged");
	if (RuleTagged  == NULL)
		err(1, "bitcode fault: RuleTagged ");
	RuleKeepState = LLVMGetTypeByName(Mod, "rule_keep_state");
	if (RuleKeepState  == NULL)
		err(1, "bitcode fault: RuleKeepState ");
	RuleCheckState = LLVMGetTypeByName(Mod, "rule_check_state");
	if (RuleCheckState  == NULL)
		err(1, "bitcode fault: RuleCheckState ");
	RuleAccept = LLVMGetTypeByName(Mod, "rule_accept");
	if (RuleAccept  == NULL)
		err(1, "bitcode fault: RuleAccept ");
	RuleQueue = LLVMGetTypeByName(Mod, "rule_queue");
	if (RuleQueue  == NULL)
		err(1, "bitcode fault: RuleQueue ");
	RuleTee = LLVMGetTypeByName(Mod, "rule_tee");
	if (RuleTee  == NULL)
		err(1, "bitcode fault: RuleTee ");
	RuleCount = LLVMGetTypeByName(Mod, "rule_count");
	if (RuleCount  == NULL)
		err(1, "bitcode fault: RuleCount ");
	RuleSkipto = LLVMGetTypeByName(Mod, "rule_skipto");
	if (RuleSkipto  == NULL)
		err(1, "bitcode fault: RuleSkipto ");
	RuleCallreturn = LLVMGetTypeByName(Mod, "rule_callreturn");
	if (RuleCallreturn  == NULL)
		err(1, "bitcode fault: RuleCallreturn ");
	RuleReject = LLVMGetTypeByName(Mod, "rule_reject");
	if (RuleReject  == NULL)
		err(1, "bitcode fault: RuleReject ");
#ifdef INET6
	RuleUnreach6 = LLVMGetTypeByName(Mod, "rule_unreach6");
	if (RuleUnreach6  == NULL)
		err(1, "bitcode fault: RuleUnreach6 ");
#endif
	RuleDeny = LLVMGetTypeByName(Mod, "rule_deny");
	if (RuleDeny  == NULL)
		err(1, "bitcode fault: RuleDeny ");
	RuleForwardIp = LLVMGetTypeByName(Mod, "rule_forward_ip");
	if (RuleForwardIp  == NULL)
		err(1, "bitcode fault: RuleForwardIp ");
#ifdef INET6
	RuleForwardIp6 = LLVMGetTypeByName(Mod, "rule_forward_ip6");
	if (RuleForwardIp6  == NULL)
		err(1, "bitcode fault: RuleForwardIp6 ");
#endif
	RuleNgtee = LLVMGetTypeByName(Mod, "rule_ngtee");
	if (RuleNgtee  == NULL)
		err(1, "bitcode fault: RuleNgtee ");
	RuleSetfib = LLVMGetTypeByName(Mod, "rule_setfib");
	if (RuleSetfib  == NULL)
		err(1, "bitcode fault: RuleSetfib ");
	RuleSetdscp = LLVMGetTypeByName(Mod, "rule_setdscp");
	if (RuleSetdscp  == NULL)
		err(1, "bitcode fault: RuleSetdscp ");
	RuleNat = LLVMGetTypeByName(Mod, "rule_nat");
	if (RuleNat  == NULL)
		err(1, "bitcode fault: RuleNat ");
	RuleReass = LLVMGetTypeByName(Mod, "rule_reass");
	if (RuleReass  == NULL)
		err(1, "bitcode fault: RuleReass ");
}

/* Allocate and initialize LLVM vars. */
/* Note: The type of the object returned by LLVMBuildAlloca */
/* is already a pointer to a given type. */
void
allocaAndInit()
{
	LLVMValueRef Int320S = LLVMConstInt(Int32Ty, 0, 1);
	LLVMValueRef Int320U = LLVMConstInt(Int32Ty, 0, 0);
	LLVMValueRef Int160U = LLVMConstInt(Int16Ty, 0, 0);
	LLVMValueRef Int80U = LLVMConstInt(Int16Ty, 0, 1);

	LLVMPositionBuilderAtEnd(Irb, Entry);

	/* Control flow variables. */
	/* int done = 0; */
	Done = LLVMBuildAlloca(Irb, Int32Ty, "done");
	LLVMBuildStore(in320S, Done);

	/* int f_pos = 0; */
	FPos = LLVMBuildAlloca(Irb, Int32Ty, "fpos");
	LLVMBuildStore(Int320S, FPos);

	/* int retval = 0; */
	Retval = LLVMBuildAlloca(Irb, Int32Ty, "retval");
	LLVMBuildStore(Int320S, Retval);

	/* m = args->m (idx: 0) */
	MPtr = LLVMBuildAlloca(Irb, MbufPtrTy, "m");
	LLVMValueRef MG = LLVMBuildStructGEP(Irb, Args, 0, NULL);
	LLVMValueRef MGL = LLVMBuildLoad(Irb, MG, NULL);
	LLVMBuildStore(Irb, MGL, MPtr);
	M = LLVMBuildLoad(Irb, MPtr);

	/* ip = (struct ip *)((m)->m_data) (idx: 2) */
	IpPtr = LLVMBuildAlloca(Irb, IpPtrTy, NULL, "ip");
	LLVMValueRef M_data = LLVMBuildStructGEP(Irb, M, 2, NULL)
	LLVMValueRef M_casted = LLVMBuildBitCast(Irb, M_data, IpPtrTy, NULL);
	LLVMBuildStore(M_casted, IpPtr);

	/* int ucred_lookup = 0; */
	Ucred_lookup = LLVMBuildAlloca(Irb, Int32Ty, NULL, "ucred_lookup");
	LLVMBuildStore(Int320S, Ucred_lookup);

	/* struct ifnet *oif = args->oif; (idx: 0) */
	Oif = LLVMBuildAlloca(Irb, IfnetTy, NULL, "oif");
	LLVMValueRef ArgsG = LLVMBuildStructGEP(Irb, Args, 1, NULL);
	LLVMValueRef ArgsGL = LLVMBuildLoad(Irb, ArgsG, Oif);
	LLVMBuildStore(Irb, ArgsGL, Oif);

	/* u_int hlen = 0;	*/
	Hlen = LLVMBuildAlloca(Irb, Int32Ty, NULL, "hlen");
	LLVMCreateStore(Irb, Int320U, Hlen);

	/* u_short offset = 0; */
	Offset = LLVMBuildAlloca(Irb, Int16Ty, NULL, "offset");
	LLVMCreateStore(Irb, Int160U, Offset);

	/* u_short ip6f_mf = 0; */
	Ip6fMf = LLVMBuildAlloca(Irb, Int16Ty, NULL, "ip6f_mf");
	LLVMCreateStore(Irb, Int160U, Ip6Mf);

	/* uint8_t proto = 0; */
	Proto = LLVMBuildAlloca(Irb, Int8Ty, NULL, "proto");
	LLVMCreateStore(Irb, Int80U, Proto);

	/* uint8_t args->f_id.proto = 0 (idx: 6, 5) */
	LLVMValueRef F_id = LLVMBuildStructGEP(Irb, Args, 6, NULL);
	LLVMValueRef FProto = Irb.CreateStructGEP(F_id, 5, NULL);
	LLVMCreateStore(Irb, Int80U, FProto);

	/* uint16_t src_port = 0, dst_port = 0;	*/
	SrcPort = LLVMBuildAlloca(Irb, Int16Ty, NULL, "src_port");
	LLVMBuildStore(Irb, Int160U, SrcPort);
	DstPort = LLVMBuildAlloca(Irb, Int16Ty, NULL, "dst_port");
	LLVMBuildStore(Irb, Int160U, DstPort);

	/* (uint32_t) src_ip.s_addr = 0; */
	SrcIp = LLVMBuildAlloca(Irb, In_addrTy, NULL, "src_ip");
	LLVMValueRef SrcSAddr = LLVMBuildStructGEP(Irb, SrcIp, 0);
	LLVMBuildStore(Irb, Int320U, SrcSAddr);
	/* (uint32_t) dst_ip.s_addr = 0; */
	DstIp = LLVMBuildAlloca(Irb, In_addrTy, NULL, "dst_ip");
	LLVMValueRef DstSAddr = LLVMBuildStructGEP(Irb, DstIp, 0);
	LLVMBuildStore(Irb, Int320U, DstSAddr);

	/* uint16_t iplen=0; */
	Iplen = LLVMBuildAlloca(Irb, Int16Ty, NULL, "iplen");
	LLVMBuildStore(Irb, Int160U, Iplen);

	/* pktlen = m->m_pkthdr.len; */
	/* m_pkthdr is the 6th element (idx: 5) */
	/* len is the 2nd element (idx: 1) */
	Pktlen = LLVMBuildAlloca(Irb, Int32Ty, NULL, "pktlen");
	LLVMValueRef Header = LLVMBuildStructGEP(Irb, M, 5);
	LLVMValueRef LengthPtr = LLVMBuildStructGEP(Irb, Header, 1);
	LLVMValueRef Length = LLLVMBuildLoad(Irb, LengthPtr);
	LLVMBuildStore(Irb, Length, Pktlen);

	/* uint16_t	etype = 0; */
	Etype = LLVMBuildAlloca(Irb, Int16Ty, NULL, "etype");
	LLVMBuildStore(Irb, Int160U, Etype);

	/* int dyn_dir = MATCH_UNKNOWN; */
	Dyn_dir = LLVMBuildAlloca(Irb, Int32Ty, NULL, "dyn_dir");
	LLVMBuildStore(Irb, LLVMConstInt(Int16Ty, MATCH_UNKNOWN, 1), Dyn_dir);

	/* ipfw_dyn_rule *q = NULL; */
	Q = LLVMBuildAlloca(Irb, Ipfw_dyn_rulePtrTy, NULL, "q");
	LLVMBuildStore(Irb, LLVMConstPointerNull(Ipfw_dyn_rulePtrTy), Q);

	/* We use Int8PtrTy as void ptr */
	/* void *ulp = NULL; */
	Ulp = LLVMBuildAlloca(Irb, Int8PtrTy, NULL, "ulp");
	LLVMBuildStore(Irb, ConstantPointerNull::get(Int8PtrTy), Ulp);

	/* int is_ipv4 = 0; */
	IsIpv4 = LLVMBuildAlloca(Irb, Int32Ty, NULL, "is_ipv4");
	LLVMBuildStore(Irb, Int320U, IsIpv4);

	/* int is_ipv6 = 0; */
	IsIpv6 = LLVMBuildAlloca(Irb, Int32Ty, NULL, "is_ipv6");
	LLVMBuildStore(Irb, Int320U, IsIpv6);

	/* uint8_t	icmp6_type = 0; */
	Icmp6Type = LLVMBuildAlloca(Irb, Int8Ty, NULL, "icmp6_type");
	LLVMBuildStore(Irb, Int80U, Icmp6Type);

	/* uint16_t ext_hd = 0; */
	ExtHd = LLVMBuildAlloca(Irb, Int16Ty, NULL, "ext_hd");
	LLVMBuildStore(Irb, Int160U, ExtHd);

	// If it returns one, goto pullup_failed.
	// Else, goto first rule.
	LLVMValueRef Ip = LLVMBuildLoad(Irb, IpPtr);
	LLVMValueRef UlpL = LLVMBuildLoad(Irb, Ulp);

	LLVMValueRef InspectPktCall = LLVMBuildCall(Irb, InspectPkt, {Args, Ip, M,
		SrcIp, DstIp, SrcPort, DstPort, Etype, ExtHd, Iplen, Pktlen, IsIpv4,
		IsIpv6, Hlen, Proto, Icmp6Type, Ip6fMf, Offset, UlpL}, 19, NULL);

	LLVMValueRef Comp = LLVMBuildICmp(Irb, LLVMIntEQ, InspectPktCall,
		LLVMConstInt(Int32Ty, 1));
	LLVMBuildCondBr(Irb, Comp, PullupFailed, CheckTag);
}

/* This is equivalent to the pullup_failed tag. */
void
emit_pullup_failed()
{
	LLVMBasicBlockRef Print = LLVMAppendBasicBlockInContext(Con, "print", Func);
	LLVMBasicBlockRef Ret = LLVMAppendBasicBlockInContext(Con, "ret", Func);

	LLVMValueRef Is_verbose, Str, Comp;

	/* VNET_DECLARE(int, fw_verbose); */
	/* #define	V_fw_verbose		VNET(fw_verbose) */
	/* We should be fine getting that from the Module. */

	/* pullup_failed: */
	/* 	if (V_fw_verbose) */
	/* 		printf("ipfw: pullup failed\n"); */
	/* 	return (IP_FW_DENY); */

	IsVerbose = LLVMGetNamedGlobal(Mod, "fw_verbose");
	Str = LLVMBuildGlobalString(Irb, "ipfw: pullup failed\n", NULL);

	LLVMPositionBuilderAtEnd(Irb, PullupFailed);

	/* if (V_fw_verbose) */
	LLVMValueRef Is_verboseL = LLVMBuildLoad(Irb, Is_verbose); 
	// XXX SIGN?
	Comp = LLVMBuildICmp(Irb, LLVMIntEQ, Is_verboseL, 
		LLVMConstInt(Int32Ty, 0, 0));
	LLVMBuildCondBr(Irb, Comp, Ret, Print);

	/* printf("ipfw: pullup failed\n"); */
	LLVMPositionBuilderAtEnd(Irb, Print);
	LLVMValueRef StrFirstElement = LLVMBuildStructGEP(Irb, Str, 0);
	LLVMBuildCall(Irb, PrintfFunc, StrFirstElement, 1, NULL);
	LLVMBuildBr(Irb, Ret);

	/* return (IP_FW_DENY); */
	LLVMPositionBuilderAtEnd(Irb, Ret);
	// XXX SIGN?
	LLVMBuildRet(Irb, LLVMConstInt(Int32Ty, IP_FW_DENY, 0));
}

void
emit_check_tag()
{
	LLVMBasicBlockRef Tagged = BasicBlock::Create(Con, "tagged", Func);
	LLVMBasicBlockRef Nottagged = BasicBlock::Create(Con, "nottagged", Func);
	LLVMBasicBlockRef Jt = BasicBlock::Create(Con, "jt", Func);
	LLVMBasicBlockRef Jf = BasicBlock::Create(Con, "jf", Func);

	LLVMValueRef Comp;

	Irb.SetInsertPoint(CheckTag);

	// if (args->rule.slot) {
	// 	/*
	// 	 * Packet has already been tagged as a result of a previous
	// 	 * match on rule args->rule aka args->rule_id (PIPE, QUEUE,
	// 	 * REASS, NETGRAPH, DIVERT/TEE...)
	// 	 * Validate the slot and continue from the next one
	// 	 * if still present, otherwise do a lookup.
	// 	 */
	// 	f_pos = (args->rule.chain_id == chain->id) ?
	// 		args->rule.slot :
	// 		ipfw_find_rule(chain, args->rule.rulenum,
	// 		args->rule.rule_id);
	// } else {
	// 	f_pos = 0;
	// }

	// if (args->rule.slot)
	LLVMValueRef Rule = Irb.CreateStructGEP(Args, 4);
	LLVMValueRef Slot = Irb.CreateStructGEP(Rule, 0);
	LLVMValueRef SlotValue = Irb.CreateLoad(Slot);
	Comp = Irb.CreateICmpEQ(SlotValue, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, Nottagged, Tagged);

	Irb.SetInsertPoint(Tagged);
	// if (args->rule.chain_id == chain->id)
	LLVMValueRef ChainId = Irb.CreateStructGEP(Rule, 3); 
	LLVMValueRef Id = Irb.CreateStructGEP(Chain, 12);
	LLVMValueRef ChainIdL = Irb.CreateLoad(ChainId);
	LLVMValueRef IdL = Irb.CreateLoad(Id);
	Comp = Irb.CreateICmpEQ(ChainIdL, IdL);
	Irb.CreateCondBr(Comp, Jt, Jf);

	// f_pos = args->rule.slot;
	Irb.SetInsertPoint(Jt);
	Irb.CreateStore(SlotValue, FPos);
	Irb.CreateBr(Nottagged);

	// else fpos = ipfw_find_rule(chain, args->rule.rulenum, args->rule.rule_id)
	Irb.SetInsertPoint(Jf);
	LLVMValueRef Rulenum = Irb.CreateStructGEP(Rule, 1);
	LLVMValueRef RulenumL = Irb.CreateLoad(Rulenum);
	LLVMValueRef RuleId = Irb.CreateStructGEP(Rule, 2);
	LLVMValueRef RuleIdL = Irb.CreateLoad(RuleId);
	LLVMValueRef FindRuleCall = Irb.CreateCall3(IpfwFindRule, Chain, RulenumL, RuleIdL);
	Irb.CreateStore(FindRuleCall, FPos);

	// Branch to Nottagged because it
	// only finishes the entry BasicBlock.
	Irb.CreateBr(Nottagged);

	// else f_pos = 0;
	// Since f_pos is initialized by default as 0, we only br.
	Irb.SetInsertPoint(Nottagged);
	Irb.CreateBr(rules[0]);
}

// Set up the compiling stuff.
void
startcompiler(int rulesnumber)
{
	int i;

	Con = LLVMGetGlobalContext();
	Irb = LLVMCreateBuilderInContext(Con);

	// Create the module and load the code.
	Mod = loadBitcode();

	Func = LLVMGetNamedFunction(Mod, "ipfw_chk_jit");
	if (Func == NULL)
		err(1, "bitcode fault: ipfw_chk_jit");
	LLVMSetLinkage(Func, LLVMExternalLinkage);

	// Create static BasicBlocks.
	// The entry basic block contains all the initialization 
	// and allocation of resources, and a basic check done 
	// before start emmiting the rules code.
	Entry = LLVMAppendBasicBlockInContext(Con, "Entry", Func);
	End = LLVMAppendBasicBlockInContext(Con, "End", Func);
	CheckTag = LLVMAppendBasicBlockInContext(Con, "CheckTag", Func);
	PullupFailed = LLVMAppendBasicBlockInContext(Con, "PullupFailed", Func);

	// Get struct types, and store vars
	setEnv();

	// Start compilation
	allocaAndInit();

	// Initialize the array.
	nrules = rulesnumer;
	rules = calloc(rulesnumber, sizeof(LLVMBasicBlockRef));
	for (i = 0; i < rulesnumber; i++)
		rules[i] = LLVMAppendBasicBlockInContext(Con, "rule", Func);

	emit_check_tag();
	emit_pullup_failed();
}

funcptr
compile()
{
	InitializeNativeTarget();
	LLVMLinkInJIT();

	// Optimise
	PassManagerBuilder PMBuilder;
	PMBuilder.OptLevel = 3;
	//PMBuilder.Inliner = createFunctionInliningPass(275);

	// Function passes
	FunctionPassManager *PerFunctionPasses = new FunctionPassManager(Mod);
	PMBuilder.populateFunctionPassManager(*PerFunctionPasses);
	PerFunctionPasses->run(*Func);
	PerFunctionPasses->doFinalization();
	delete PerFunctionPasses;

	// We don't need it anymore.
	Function *vf = mod->getFunction("voidfunction");
	vf->eraseFromParent();

	//Compile
	std::string errstr;

	EngineBuilder EB = EngineBuilder(std::unique_ptr<Module>(mod));
	//EB.setEngineKind(EngineKind::Kind::JIT);
	EB.setErrorStr(&errstr);
	EB.setOptLevel(CodeGenOpt::Level::Aggressive);
	EB.setUseMCJIT(true);
	EB.setVerifyModules(true);

	ExecutionEngine *EE = EB.create();
	if (!EE) {
		fprintf(stderr, "Compilation error: %s\n", errstr.c_str());
		exit(1);
	}

	// XXX We should use a NON deperecated function.
	return (funcptr)EE->getPointerToFunction(mod->getFunction("ipfw_chk_jit"));
}

void
end_rule()
{
	rulenumber++;
}

void
emit_outer_for_prologue()
{
	LLVMBasicBlockRef jt = BasicBlock::Create(Con, "jt", Func);
	LLVMBasicBlockRef jf = BasicBlock::Create(Con, "jf", Func);

	LLVMValueRef SetDisable = mod->getGlobalVariable("set_disable");

	// ipfw_insn *cmd;
	// uInt32_t tablearg = 0;
	// int l, cmdlen, skip_or; /* skip rest of OR block */
	// struct ip_fw *f;
	// f = chain->map[f_pos];
	// if (V_set_disable & (1 << f->set) )
	// 	continue;
	// skip_or = 0;

	// Write at the current rule.
	Irb.SetInsertPoint(rules[rulenumber]);

	// ipfw_insn *cmd;
	// uInt32_t tablearg = 0;
	// int l, cmdlen, skip_or; /* skip rest of OR block */
	Cmd = Irb.CreateAlloca(Ipfw_insnPtrTy, nullptr, "cmd");
	Tablearg = Irb.CreateAlloca(Int32Ty, nullptr, "tablearg");
	L = Irb.CreateAlloca(Int32Ty, nullptr, "l");
	Cmdlen = Irb.CreateAlloca(Int32Ty, nullptr, "cmdlen");
	SkipOr = Irb.CreateAlloca(Int32Ty, nullptr, "skipor");
	F = Irb.CreateAlloca(Ip_fwPtrTy, nullptr, "f");

	// uInt32_t tablearg = 0;
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Tablearg);

	// f = chain->map[f_pos]; idxs: 5, f_pos
	LLVMValueRef FPosL = Irb.CreateLoad(FPos);
	LLVMValueRef ExtFPos = Irb.CreateSExt(FPosL, Int64Ty);
	LLVMValueRef Map = Irb.CreateStructGEP(Chain, 5);
	LLVMValueRef MapL = Irb.CreateLoad(Map);
	LLVMValueRef MapFPos = Irb.CreateInBoundsGEP(MapL, ExtFPos);
	LLVMValueRef MapFPosL = Irb.CreateLoad(MapFPos);
	Irb.CreateStore(MapFPosL, F);

	// if (V_set_disable & (1 << f->set) )
	LLVMValueRef FL = Irb.CreateLoad(F);
	LLVMValueRef Set = Irb.CreateStructGEP(FL, 5);
	LLVMValueRef SetL = Irb.CreateLoad(Set); //uint8
	LLVMValueRef ShiftedSet = Irb.CreateShl(ConstantInt::get(Int8Ty, 1), SetL);
	LLVMValueRef SetDisableL = Irb.CreateLoad(SetDisable);
	LLVMValueRef ShiftedSet32 = Irb.CreateZExt(ShiftedSet, Int32Ty);
	LLVMValueRef AndOp = Irb.CreateAnd(SetDisableL, ShiftedSet32);
	LLVMValueRef Comp = Irb.CreateICmpNE(AndOp, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, jt, jf);

	Irb.SetInsertPoint(jt);
	//		continue;
	Irb.CreateBr(nextRule());

	// skip_or = 0;
	Irb.SetInsertPoint(jf);
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), SkipOr);
}

void
emit_inner_for_prologue()
{
	LLVMBasicBlockRef firstt = BasicBlock::Create(Con, "firstt", Func);
	LLVMBasicBlockRef firstf = BasicBlock::Create(Con, "firstf", Func);
	LLVMBasicBlockRef secondt = BasicBlock::Create(Con, "secondt", Func);
	LLVMBasicBlockRef secondf = BasicBlock::Create(Con, "secondf", Func);

	LLVMValueRef Comp, AndOp;

	// The first two are initializers of the outer for.
	//	l = f->cmd_len;
	//	cmd = f->cmd;
	//
	// 	int match;
	// 	cmdlen = F_LEN(cmd);
	// 	if (skip_or) {		/* skip this instruction */
	// 		if ((cmd->len & F_OR) == 0)
	// 			skip_or = 0;	/* next one is good */
	// 		continue;
	// 	}
	// 	match = 0; /* set to 1 if we succeed */

	// l = f->cmd_len;
	LLVMValueRef FL = Irb.CreateLoad(F);
	LLVMValueRef FCmdlen = Irb.CreateStructGEP(FL, 3);
	LLVMValueRef FCmdlenL = Irb.CreateLoad(FCmdlen);
	LLVMValueRef FCmdlenL32 = Irb.CreateZExt(FCmdlenL, Int32Ty);
	Irb.CreateStore(FCmdlenL32, L);

	// cmd = f->cmd;
	LLVMValueRef FCmd = Irb.CreateStructGEP(FL, 11);
	LLVMValueRef Addr = Irb.CreateBitCast(FCmd, Ipfw_insnPtrTy);
	Irb.CreateStore(Addr, Cmd);

	// int match;
	Match = Irb.CreateAlloca(Int32Ty, nullptr, "match");

	// int cmdlen;
	// cmdlen = ((cmd)->len & F_LEN_MASK);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef LenPtr = Irb.CreateStructGEP(CmdL, 1);
	LLVMValueRef Len = Irb.CreateLoad(LenPtr);
	AndOp = Irb.CreateAnd(Len, ConstantInt::get(Int8Ty, F_LEN_MASK));
	LLVMValueRef AndOp32 = Irb.CreateSExt(AndOp, Int32Ty);
	Irb.CreateStore(AndOp32, Cmdlen);

	// if (skip_or)
	LLVMValueRef SkipOrL = Irb.CreateLoad(SkipOr);
	Comp = Irb.CreateICmpNE(SkipOrL, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, firstt, firstf);

	Irb.SetInsertPoint(firstt);
	// if ((cmd->len & F_OR) == 0)
	AndOp = Irb.CreateAnd(Len, ConstantInt::get(Int8Ty, F_OR));
	Comp = Irb.CreateICmpEQ(AndOp, ConstantInt::get(Int8Ty, 0));
	Irb.CreateCondBr(Comp, secondt, secondf);

	Irb.SetInsertPoint(secondt);
	// skip_or = 0;
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), SkipOr);
	Irb.CreateBr(secondf);

	Irb.SetInsertPoint(secondf);
	// continue;
	Irb.CreateBr(nextRule());

	Irb.SetInsertPoint(firstf);
	// match = 0;
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Match);
}


// We get here ar the end of switch() on opcodes.
void
emit_inner_for_epilogue()
{
	LLVMBasicBlockRef matchnz = BasicBlock::Create(Con, "matchnz", Func);
	LLVMBasicBlockRef matchz = BasicBlock::Create(Con, "matchz", Func);
	LLVMBasicBlockRef jt = BasicBlock::Create(Con, "jt", Func);
	LLVMBasicBlockRef sec_cond = BasicBlock::Create(Con, "sec_cond", Func);
	LLVMBasicBlockRef matchzero = BasicBlock::Create(Con, "matchzero", Func);
	LLVMBasicBlockRef matchnotzero = BasicBlock::Create(Con, "matchnotzero", Func);
	LLVMBasicBlockRef is_or = BasicBlock::Create(Con, "is_or", Func);
	LLVMBasicBlockRef Continue = BasicBlock::Create(Con, "Continue", Func);

	LLVMValueRef Comp, AndOp;

	// This are the increments of the for loop.
	// l -= cmdlen, cmd += cmdlen;
	LLVMValueRef LL = Irb.CreateLoad(L);
	LLVMValueRef CmdlenL = Irb.CreateLoad(Cmdlen);
	LLVMValueRef Sub = Irb.CreateNSWSub(LL, CmdlenL);
	Irb.CreateStore(Sub, L);

	// ipfw_insn *cmd; Add to pointer.
	// Note: Since LLVM can't add to a ptr, we can use GEP with casted Ptr.
	// cmd += cmdlen;
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef Add = Irb.CreateInBoundsGEP(CmdL, CmdlenL);
	Irb.CreateStore(Add, Cmd);

	// if (cmd->len & F_NOT)
	// 	match = !match;
	//
	// if (match) {
	// 	if (cmd->len & F_OR)
	// 		skip_or = 1;
	// } else {
	// 	if (!(cmd->len & F_OR)) /* not an OR block, */
	// 		break;		/* try next rule    */
	// }

	// if (cmd->len & F_NOT)
	LLVMValueRef Len = Irb.CreateStructGEP(CmdL, 1);
	LLVMValueRef LenL = Irb.CreateLoad(Len);
	AndOp = Irb.CreateAnd(LenL, ConstantInt::get(Int8Ty, F_NOT));
	Comp = Irb.CreateICmpNE(AndOp, ConstantInt::get(Int8Ty, 0));
	Irb.CreateCondBr(Comp, jt, sec_cond);

	Irb.SetInsertPoint(jt);
	// match = !match;
	// match = ((match)?0:1);
	LLVMValueRef MatchL = Irb.CreateLoad(Match);
	Comp = Irb.CreateICmpNE(MatchL, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, matchnz, matchz);

	Irb.SetInsertPoint(matchnz);
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Match);
	Irb.CreateBr(sec_cond);

	Irb.SetInsertPoint(matchz);
	Irb.CreateStore(ConstantInt::get(Int32Ty, 1), Match);
	Irb.CreateBr(sec_cond);

	Irb.SetInsertPoint(sec_cond);
	// if (match)
	MatchL = Irb.CreateLoad(Match);
	Comp = Irb.CreateICmpNE(MatchL, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, matchnotzero, matchzero);

	Irb.SetInsertPoint(matchnotzero);
	// if (cmd->len & F_OR)
	AndOp = Irb.CreateAnd(LenL, ConstantInt::get(Int8Ty, F_OR));
	Comp = Irb.CreateICmpNE(AndOp, ConstantInt::get(Int8Ty, 0));
	Irb.CreateCondBr(Comp, is_or, Continue);

	Irb.SetInsertPoint(is_or);
	// skip_or = 1;
	Irb.CreateStore(ConstantInt::get(Int32Ty, 1), SkipOr);
	Irb.CreateBr(Continue);

	Irb.SetInsertPoint(matchzero);
	// if (!(cmd->len & F_OR)) /* not an OR block, */
	//     break;
	AndOp = Irb.CreateAnd(LenL, ConstantInt::get(Int8Ty, F_OR));
	Comp = Irb.CreateICmpEQ(AndOp, ConstantInt::get(Int8Ty, 0));
	Irb.CreateCondBr(Comp, nextRule() /* break */, Continue);
	
	Irb.SetInsertPoint(Continue);
}


// This code gets executed at the end of inner loop.
// In this context, break means goto end, else continue loop.
void
emit_outer_for_epilogue()
{
	// f_pos++, increment of the for loop.
	LLVMValueRef FPosL = Irb.CreateLoad(FPos);
	LLVMValueRef AddOp = Irb.CreateAdd(FPosL, ConstantInt::get(Int32Ty, 1));
	Irb.CreateStore(AddOp, FPos);

	// if (done)
	//		break;
	LLVMValueRef DoneL = Irb.CreateLoad(Done);
	LLVMValueRef Comp = Irb.CreateICmpNE(DoneL, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, End, nextRule());
}


void
emit_end()
{
	LLVMValueRef Rule, TimeUptime, Str;

	LLVMBasicBlockRef Jt = BasicBlock::Create(Con, "jt", Func);
	LLVMBasicBlockRef Jf = BasicBlock::Create(Con, "jf", Func);
	LLVMBasicBlockRef Ret = BasicBlock::Create(Con, "ret", Func);
	LLVMValueRef Comp, AddOp;

	// if (done) {
	//		struct ip_fw *rule = chain->map[f_pos];
	//		/* Update statistics */
	//		(rule)->pcnt++;
	//		(rule)->bcnt += pktlen;
	//		(rule)->timestamp = time_uptime;
	// } else {
	//		retval = IP_FW_DENY;
	//		printf("ipfw: ouch!, skip past end of rules, denying packet\n");
	// }
	//
	// return (retval);

	Irb.SetInsertPoint(End);

	// We need to get the timestamp variable.
	TimeUptime = mod->getGlobalVariable("time_uptime");
	Str = Irb.CreateGlobalString("ipfw: ouch!, skip past end of rules, denying packet\n");

	// if (done)
	LLVMValueRef DoneL = Irb.CreateLoad(Done);
	Comp = Irb.CreateICmpNE(DoneL, ConstantInt::get(Int32Ty, 0));
	Irb.CreateCondBr(Comp, Jt, Jf);

	Irb.SetInsertPoint(Jt);
	// struct ip_fw *rule = chain->map[f_pos];
	Rule = Irb.CreateAlloca(Ip_fwPtrTy, nullptr, "rule");
	LLVMValueRef FPosL = Irb.CreateLoad(FPos);
	LLVMValueRef ExtFPos = Irb.CreateSExt(FPosL, Int64Ty);
	LLVMValueRef Map = Irb.CreateStructGEP(Chain, 5);
	LLVMValueRef MapL = Irb.CreateLoad(Map);
	LLVMValueRef MapFPos = Irb.CreateInBoundsGEP(MapL, ExtFPos);
	LLVMValueRef MapFPosL = Irb.CreateLoad(MapFPos);
	Irb.CreateStore(MapFPosL, Rule);

	// uint64_t pcnt;
	// (rule)->pcnt++;
	LLVMValueRef RuleL = Irb.CreateLoad(Rule);
	LLVMValueRef Pcnt = Irb.CreateStructGEP(RuleL, 8);
	LLVMValueRef PcntL = Irb.CreateLoad(Pcnt);
	AddOp = Irb.CreateAdd(PcntL, ConstantInt::get(PcntL->getType(), 1));
	Irb.CreateStore(AddOp, Pcnt);

	// uint64_t bnct;
	// int32_t pktlen
	// (rule)->bcnt += pktlen;
	LLVMValueRef Bcnt = Irb.CreateStructGEP(RuleL, 9);
	LLVMValueRef BcntL = Irb.CreateLoad(Bcnt);
	LLVMValueRef PktlenL = Irb.CreateLoad(Pktlen);
	LLVMValueRef PktlenL64 = Irb.CreateZExt(PktlenL, Int64Ty);
	AddOp = Irb.CreateAdd(BcntL, PktlenL64);
	Irb.CreateStore(AddOp, Bcnt);

	// We have to fit 64 bits into 32
	// (rule)->timestamp = time_uptime;
	// uInt32_t timestamp;
	// int64_t time_uptime;
	LLVMValueRef TimeUptimeL = Irb.CreateLoad(TimeUptime);
	LLVMValueRef TimeUptimeL32 = Irb.CreateTrunc(TimeUptimeL, Int32Ty);
	LLVMValueRef Timestamp = Irb.CreateStructGEP(RuleL, 10);
	Irb.CreateStore(TimeUptimeL32, Timestamp);
	Irb.CreateBr(Ret);

	Irb.SetInsertPoint(Jf);
	//	retval = IP_FW_DENY;
	//	printf("ipfw: ouch!, skip past end of rules, denying packet\n");
	Irb.CreateStore(ConstantInt::get(Int32Ty, IP_FW_DENY), Retval);
	LLVMValueRef StrFirstElement = Irb.CreateStructGEP(Str, 0);
	Irb.CreateCall(PrintfFunc, StrFirstElement);
	Irb.CreateBr(Ret);

	//Return retval
	Irb.SetInsertPoint(Ret);
	LLVMValueRef RetvalL = Irb.CreateLoad(Retval);
	Irb.CreateRet(RetvalL);
}


// Rules
// XXX Exec not tested.
void
emit_nop()
{
	// rule_nop(&match);
	Irb.CreateCall(RuleNop, Match);
}

// XXX Exec not tested.
void
emit_forward_mac()
{
	// rule_forward_mac(cmd->opcode);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef Opcode = Irb.CreateStructGEP(CmdL, 0);
	LLVMValueRef OpcodeL = Irb.CreateLoad(Opcode);
	// Opcode is u_int8
	LLVMValueRef OpcodeL32 = Irb.CreateZExt(OpcodeL, Int32Ty);
	Irb.CreateCall(RuleForwardMac, {OpcodeL32});
}

// XXX Exec not tested.
void
emit_jail()
{
	// rule_jail(&match, offset, proto, cmd, args, ucred_lookup, ucred_cache);
	// We roll our own version because we don't have ucred_lookup.

	LLVMBasicBlockRef OffsetNZ = BasicBlock::Create(Con, "R_offsetnotzero", Func);
	LLVMBasicBlockRef OffsetZE = BasicBlock::Create(Con, "R_offsetiszero", Func);
	LLVMBasicBlockRef TCPorUDP = BasicBlock::Create(Con, "R_setmatchzero", Func);
	LLVMBasicBlockRef Continue = BasicBlock::Create(Con, "R_Continue", Func);
	LLVMValueRef Comp;

	// if (offset != 0)
	//		break;
	// if (proto == IPPROTO_TCP ||
	// 	proto == IPPROTO_UDP)
	//		*match = 0;

	// if (offset != 0)
	//		break;
	LLVMValueRef OffsetL = Irb.CreateLoad(Offset);
	Comp = Irb.CreateICmpNE(OffsetL, ConstantInt::get(Int16Ty, 0));
	Irb.CreateCondBr(Comp, OffsetNZ, OffsetZE);

	Irb.SetInsertPoint(OffsetNZ);
	// Go to next rule.
	Irb.CreateBr(nextRule());

	// if (proto == IPPROTO_TCP ||
	// 	proto == IPPROTO_UDP)
	//		*match = 0;
	Irb.SetInsertPoint(OffsetZE);
	LLVMValueRef ProtoL = Irb.CreateLoad(Proto);
	Comp = Irb.CreateICmpEQ(OffsetL, ConstantInt::get(OffsetL->getType(), IPPROTO_TCP));
	LLVMValueRef Comp2 = Irb.CreateICmpEQ(OffsetL, ConstantInt::get(OffsetL->getType(), IPPROTO_UDP));
	Irb.CreateCondBr(Comp, TCPorUDP, Continue);
	Irb.CreateCondBr(Comp2, TCPorUDP, Continue);

	Irb.SetInsertPoint(TCPorUDP);
	Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Match);
	Irb.CreateBr(Continue);

	// Keep on with the for epilogue.
	Irb.SetInsertPoint(Continue);
}

// XXX Exec not tested.
void
emit_recv()
{
	// rule_recv(&match, cmd, m, chain, &tablearg);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleRecv, {Match, CmdL, M, Chain, Tablearg});
}

// XXX Exec not tested.
void
emit_xmit()
{
	// rule_xmit(&match, oif, cmd, chain, &tablearg);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleXmit, {Match, Oif, CmdL, Chain, Tablearg});
}

// XXX Exec not tested.
void
emit_via()
{
	// rule_via(&match, oif, m, cmd, chain, &tablearg);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleVia, {Match, Oif, M, CmdL, Chain, Tablearg});
}

void
emit_macaddr2()
{
	// rule_macaddr2(&match, args, cmd);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleMacaddr2, {Match, Args, CmdL});
}

void
emit_mac_type()
{
	// rule_mac_type(&match, args, cmd, cmdlen, etype);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef CmdlenL = Irb.CreateLoad(Cmdlen);
	LLVMValueRef EtypeL = Irb.CreateLoad(Etype);
	Irb.CreateCall(RuleMacType, {Match, Args, CmdL, CmdlenL, EtypeL});
}

// XXX Exec not tested.
void
emit_frag()
{
	// rule_frag(&match, offset);
	LLVMValueRef OffsetL = Irb.CreateLoad(Offset);
	Irb.CreateCall(RuleFrag, {Match, OffsetL});
}

// XXX Exec not tested.
void
emit_in()
{
	// rule_in(&match, oif);
	Irb.CreateCall(RuleIn, {Match, Oif});
}

// XXX Exec not tested.
void
emit_layer2()
{
	// rule_layer2(&match, args);
	Irb.CreateCall(RuleLayer2, {Match, Args});
}

void
emit_diverted()
{
	// rule_diverted(&match, args, cmd);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleDiverted, {Match, Args, CmdL});
}

void
emit_proto()
{
	// rule_proto(&match, proto, cmd);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef ProtoL = Irb.CreateLoad(Proto);
	Irb.CreateCall(RuleProto, {Match, ProtoL, CmdL});
}

// XXX Exec not tested.
void
emit_ip_src()
{
	// rule_ip_src(&match, is_ipv4, cmd, &src_ip);
	LLVMValueRef IsIpv4L = Irb.CreateLoad(IsIpv4);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleIpSrc, {Match, IsIpv4L, CmdL, SrcIp});
}

void
emit_ip_dst_lookup()
{
	// XXX TODO: Recover the Values for Ucred*.
	// rule_ip_dst_lookup(&match, cmd, cmdlen, args, &tablearg, 
	//                    is_ipv4, is_ipv6, ip, &dst_ip, &src_ip, dst_port,
	//                    src_port, offset, proto, ucred_lookup, 
	//                    ucred_cache, chain);
	// Irb.CreateCall(RuleIpDstLookup, {Match, CmdL, CmdlenL, Args, Tablearg,
	// 			   IsIpv4L, IsIpv6L, IpL, DstIp, SrcIp, DstPort, SrcPort,
	// 			   OffsetL, ProtoL, UcredLookup, UcredCache, Chain});
}

void
emit_ip_dst_mask()
{
}

void
emit_ip_src_me()
{
}

void
emit_ip6_src_me()
{
}

void
emit_ip_src_set()
{
}

// XXX Exec not tested.
void
emit_ip_dst()
{
	LLVMValueRef IsIpv4L = Irb.CreateLoad(IsIpv4);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	Irb.CreateCall(RuleIpDst, {Match, IsIpv4L, CmdL, DstIp});
}

void
emit_ip_dst_me()
{
}

void
emit_ip6_dst_me()
{
}

// XXX Exec not tested.
void
emit_ip_dstport()
{
	// rule_ip_dstport(&match, proto, offset, cmd, cmdlen, dst_port, src_port);
	LLVMValueRef ProtoL = Irb.CreateLoad(Proto);
	LLVMValueRef OffsetL = Irb.CreateLoad(Offset);
	LLVMValueRef CmdL = Irb.CreateLoad(Cmd);
	LLVMValueRef CmdlenL = Irb.CreateLoad(Cmdlen);
	LLVMValueRef DstPortL = Irb.CreateLoad(DstPort);
	LLVMValueRef SrcPortL = Irb.CreateLoad(SrcPort);

	Irb.CreateCall(RuleIpDstport, {Match, ProtoL, OffsetL, CmdL, CmdlenL, DstPortL, SrcPortL});
}

void
emit_icmptype()
{
}

void
emit_icmp6type()
{
}

void
emit_ipopt()
{
}

void
emit_ipver()
{
}

void
emit_ipttl()
{
}

void
emit_ipprecedence()
{
}

void
emit_iptos()
{
}

void
emit_dscp()
{
}

void
emit_tcpdatalen()
{
}

void
emit_tcpflags()
{
}

void
emit_tcpopts()
{
	// if (rule_tcpopts(&match, hlen, ulp, proto, offset, cmd, m, args))
	// 	goto pullup_failed;
}

void
emit_tcpseq()
{
}

void
emit_tcpack()
{
}

void
emit_tcpwin()
{
}

void
emit_estab()
{
}

void
emit_altq()
{
}

void
emit_log()
{
}

void
emit_prob()
{
}

void
emit_verrevpath()
{
}

void
emit_versrcreach()
{
}

void
emit_antispoof()
{
}

void
emit_ipsec()
{
}

void
emit_ip6_src()
{
}

void
emit_ip6_dst()
{
}

void
emit_ip6_dst_mask()
{
}

void
emit_flow6id()
{
}

void
emit_ext_hdr()
{
}

void
emit_ip6()
{
}

void
emit_ip4()
{
}

void
emit_tag()
{
}

void
emit_fib()
{
}

void
emit_sockarg()
{
}

void
emit_tagged()
{
}

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

void
emit_keep_state()
{
}

void
emit_check_state()
{
}

void
emit_accept()
{
	// rule_deny(&l, &done, &retval);
	Irb.CreateCall(RuleAccept, {L, Done, Retval});
}

void
emit_queue()
{
}

void
emit_tee()
{
}

void
emit_count()
{
}

// TODO
void
emit_skipto()
{
	// IPFW_INC_RULE_COUNTER(f, pktlen);
	// f_pos = jump_fast(chain, f, cmd->arg1, tablearg, 0);
	// /*
	//  * Skip disabled rules, and re-enter
	//  * the inner loop with the correct
	//  * f_pos, f, l and cmd.
	//  * Also clear cmdlen and skip_or
	//  */
	// for (; f_pos < chain->n_rules - 1 &&
	//	   (V_set_disable &
	//	    (1 << chain->map[f_pos]->set));
	//	   f_pos++)
	// ;
	// /* Re-enter the inner loop at the skipto rule. */
	// f = chain->map[f_pos];
	// l = f->cmd_len;
	// cmd = f->cmd;
	// match = 1;
	// cmdlen = 0;
	// skip_or = 0;
	// continue;
}

void
emit_callreturn()
{
}

void
emit_reject()
{
}

void
emit_unreach6()
{
}

// XXX Exec not tested.
void
emit_deny()
{
	// rule_deny(&l, &done, &retval);
	Irb.CreateCall(RuleDeny, {L, Done, Retval});
}

void
emit_forward_ip()
{
}

void
emit_forward_ip6()
{
}

void
emit_ngtee()
{
}

void
emit_setfib()
{
}

void
emit_setdscp()
{
}

void
emit_nat()
{
}

void
emit_reass()
{
}

// Function to test compilation code.
// Filtering code has to be tested by real usage.
void
test_compilation()
{
	printf("Creating object\n");
	startcompiler(1);
	printf("emit_outer_for_prologue()\n");
	emit_outer_for_prologue();
	printf("emit_inner_for_prologue()\n");
	emit_inner_for_prologue();
	// Rule to test
	printf("Testing rule compilation\n");
	emit_proto();
	printf("emit_inner_for_epilogue()\n");
	emit_inner_for_epilogue();
	printf("emit_outer_for_epilogue()\n");
	emit_outer_for_epilogue();
	end_rule();
	printf("emit_end()\n");
	emit_end();
	err(1, "Compilation");
}

funcptr
compile_code(struct ip_fw_args *args, struct ip_fw_chain *chain)
{
	int res;
	int f_pos = 0;

	// Nothing to compile.
	if (chain->n_rules == 0)
		return (NULL);

	//test_compilation();
	startcompiler(chain->n_rules);

	// Iterate through the rules.
	int pktlen = args->m->m_pkthdr.len;

	// For all the number of rules.
	// It seems that we can create a control flow based on this.
	for (; f_pos < chain->n_rules; f_pos++) {
		ipfw_insn *cmd;
		int l, cmdlen, skip_or; /* skip rest of OR block */
		struct ip_fw *f;

		f = chain->map[f_pos];

		// Rule start.
		emit_outer_for_prologue();

		// For each different command.
		for (l = f->cmd_len, cmd = f->cmd ; l > 0 ;
		    l -= cmdlen, cmd += cmdlen) {
/* check_body: */
			cmdlen = F_LEN(cmd);
			emit_inner_for_prologue();
			switch (cmd->opcode) {
			printf("compiling opcode: %d\n", cmd->opcode);
			case O_NOP:
				emit_nop();
				break;

			// XXX Not implemented in netmap-ipfw
			case O_FORWARD_MAC:
				emit_forward_mac();
				break;

			case O_GID:
			case O_UID:
			case O_JAIL:
				emit_jail();
				break;

			case O_RECV:
				emit_recv();
				break;

			case O_XMIT:
				emit_xmit();
				break;

			case O_VIA:
				emit_via();
				break;

			case O_MACADDR2:
				emit_macaddr2();
				break;

			case O_MAC_TYPE:
				emit_mac_type();
				break;

			case O_FRAG:
				emit_frag();
				break;

			case O_IN:
				emit_in();
				break;

			case O_LAYER2:
				emit_layer2();
				break;

			case O_DIVERTED:
				emit_diverted();
				break;

			case O_PROTO:
				emit_proto();
				break;

			case O_IP_SRC:
				emit_ip_src();
				break;

			case O_IP_SRC_LOOKUP:
			case O_IP_DST_LOOKUP:
				
				break;

			case O_IP_SRC_MASK:
			case O_IP_DST_MASK:
				emit_ip_dst_mask();
				break;

			case O_IP_SRC_ME:
				emit_ip_src_me();
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_SRC_ME:
				emit_ip6_src_me();
#endif
				break;

			case O_IP_DST_SET:
			case O_IP_SRC_SET:
				emit_ip_src_set();
				break;

			case O_IP_DST:
				emit_ip_dst();
				break;

			case O_IP_DST_ME:
				
				
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_DST_ME:
				emit_ip6_dst_me();
#endif
				break;


			case O_IP_SRCPORT:
			case O_IP_DSTPORT:
				emit_ip_dstport();
				break;

			case O_ICMPTYPE:
				emit_icmptype();
				break;

#ifdef INET6
			case O_ICMP6TYPE:
				emit_icmp6type();
				break;
#endif /* INET6 */
			case O_IPOPT:
				emit_ipopt();
				break;

			case O_IPVER:
				emit_ipver();
				break;

			case O_IPID:
			case O_IPLEN:
			case O_IPTTL:
				emit_ipttl();
				break;

			case O_IPPRECEDENCE:
				emit_ipprecedence();
				break;

			case O_IPTOS:
				emit_iptos();
				break;

			case O_DSCP:
				emit_dscp();
				break;

			case O_TCPDATALEN:
				emit_tcpdatalen();
				break;

			case O_TCPFLAGS:
				emit_tcpflags();
				break;

			case O_TCPOPTS:
				emit_tcpopts();
				break;

			case O_TCPSEQ:
				emit_tcpseq();
				break;

			case O_TCPACK:
				emit_tcpack();
				break;

			case O_TCPWIN:
				emit_tcpwin();
				break;

			case O_ESTAB:
				emit_estab();
				break;

			case O_ALTQ:
				emit_altq();
				break;

			case O_LOG:
				emit_log();
				break;

			case O_PROB:
				emit_prob();
				break;

			case O_VERREVPATH:
				emit_verrevpath();
				break;

			case O_VERSRCREACH:
				emit_versrcreach();
				break;

			case O_ANTISPOOF:
				emit_antispoof();
				break;

			case O_IPSEC:
#ifdef IPSEC
				emit_ipsec();
#endif
				/* otherwise no match */
				break;

#ifdef INET6
			case O_IP6_SRC:
				emit_ip6_src();
				break;

			case O_IP6_DST:
				emit_ip6_dst();
				break;

			case O_IP6_SRC_MASK:
			case O_IP6_DST_MASK:
				emit_ip6_dst_mask();
				break;

			case O_FLOW6ID:
				emit_flow6id();
				break;

			case O_EXT_HDR:
				emit_ext_hdr();
				break;

			case O_IP6:
				emit_ip6();
				break;
#endif

			case O_IP4:
				emit_ip4();
				break;

			case O_TAG: 
				emit_tag();
				break;

			case O_FIB: /* try match the specified fib */
				emit_fib();
				break;

			case O_SOCKARG:
				emit_sockarg();
				break;

			case O_TAGGED:
				emit_tagged();
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
				emit_keep_state();
				break;

			case O_PROBE_STATE:
			case O_CHECK_STATE:
				emit_check_state();
				break;

			case O_ACCEPT:
				emit_accept();
				break;

			case O_PIPE:
			case O_QUEUE:
				emit_queue();
				break;

			case O_DIVERT:
			case O_TEE:
				emit_tee();
				break;

			case O_COUNT:
				emit_count();
				break;

			case O_SKIPTO:
				emit_skipto();
			    continue;
			    break;	/* NOTREACHED */

			case O_CALLRETURN:
				emit_callreturn();
				continue;
				break;	/* NOTREACHED */

			case O_REJECT:
				emit_reject();
				/* FALLTHROUGH */
#ifdef INET6
			case O_UNREACH6:
				emit_unreach6();
				/* FALLTHROUGH */
#endif
			case O_DENY:
				emit_deny();
				break;

			case O_FORWARD_IP:
				emit_forward_ip();
				break;

#ifdef INET6
			case O_FORWARD_IP6:
				emit_forward_ip6();
				break;
#endif

			case O_NETGRAPH:
			case O_NGTEE:
				emit_ngtee();
				break;

			case O_SETFIB:
				emit_setfib();
				break;

			case O_SETDSCP:
				emit_setdscp();
				break;

			case O_NAT:
				emit_nat();
				break;

			case O_REASS:
				emit_reass();
				break;

			default:
				panic("-- unknown opcode %d\n", cmd->opcode);
			} /* end of switch() on opcodes */
			emit_inner_for_epilogue();
		}	/* end of inner loop, scan opcodes */
		// Rule ends.
		emit_outer_for_epilogue();
		end_rule();
	}		/* end of outer for, scan rules */

	emit_end();

	// Once we're done iterating through the rules, return the pointer.
	return (compile());
}
