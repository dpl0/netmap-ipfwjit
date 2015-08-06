#undef _KERNEL
#include <iostream>
#include <string>
#include <vector>

#include <llvm/Analysis/Passes.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/CodeGen/MachineCodeInfo.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/PassManager.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#define _KERNEL

extern "C" {
#include <glue.h>
#include <missing.h>
#include <err.h>

#include <sys/mbuf.h>
#include <sys/types.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <netinet/in_pcb.h>

#include <netpfil/ipfw/dn_heap.h>
#include <netpfil/ipfw/ip_dn_private.h>
#include <netpfil/ipfw/ip_fw_private.h>
}

typedef int (*funcptr)();

using namespace llvm;

// if (logging) {
// 	Value *Str = Irb.CreateGlobalString("\nipfw_chk_jit(): firstf\n\n");
// 	Value *StrFirstElement = Irb.CreateStructGEP(Str, 0);
// 	Irb.CreateCall(PrintfFunc, StrFirstElement);
// }

class ipfwJIT {
	Module *mod;
	Function *Func;
	LLVMContext &Con;
	IRBuilder<> Irb;

	// We'll store the BasicBlock objects for each rule here.
	int rulenumber = 0;
	std::vector<BasicBlock *> rules;

	// Vars Types
	Type *Int8Ty;
	Type *Int16Ty;
	Type *Int32Ty;
	Type *Int64Ty;
	PointerType *Int8PtrTy;
	PointerType *Int16PtrTy;

	// Basic blocks used
	BasicBlock *Entry;
	BasicBlock *End;
	BasicBlock *PullupFailed;
	BasicBlock *CheckTag;

	// JIT Compiled Vars
	// These are the function arguments.
	Value *Args;
	Value *Chain;
	// Loop control.
	Value *Match;
	Value *L;
	Value *M;
	Value *Done;
	Value *FPos;
	Value *Retval;
	Value *Cmd;
	Value *Cmdlen;
	Value *Tablearg;
	Value *SkipOr;
	Value *F;

	// Packet matching variables.
	Value *MPtr;
	Value *IpPtr;
	Value *UcredCache;
	Value *UcredLookup;
	Value *Oif;
	Value *Hlen; //unsigned
	Value *Offset; //unsigned
	Value *Ip6fMf; //unsigned

	// Local copies of vars.
	// On optimization, unused ones will not be included.
	Value *Proto; //unsigned
	Value *SrcPort; //unsigned
	Value *DstPort; //unsigned
	Value *SrcIp;
	Value *DstIp;
	Value *Iplen; //unsigned
	Value *Pktlen;
	Value *Etype; //unsigned
	Value *DynDir;
	Value *Q;
	Value *Ulp;

	Value *IsIpv4;
	Value *IsIpv6;
	Value *Icmp6Type; //unsigned
	Value *ExtHd; //unsigned

	// This sets up some vars, at star time.
	Function *InspectPkt;

	// Auxiliary functions used by our JITed code.
	// All this are used from our bitcode.
	Function *IsIcmpQuery;
	Function *FlagsMatch;
	Function *IpoptsMatch;
	Function *TcpoptsMatch;
	Function *IfaceMatch;
	Function *VerifyPath;
#ifdef INET6
	Function *Icmp6typeMatch;
	Function *SearchIp6AddrNet;
	Function *Flow6idMatch;
	Function *VerifyPath6;
	Function *IsIcmp6Query;
	Function *SendReject6;
#endif /* INET6 */
	Function *SendReject;
	Function *SetMatch;
	Function *JumpFast;

	// External functions
	Function *PrintfFunc;
	Function *IpfwFindRule;

	// Rules
	Function *RuleNop;
	Function *RuleForwardMac;
	Function *RuleJail;
	Function *RuleRecv;
	Function *RuleXmit;
	Function *RuleVia;
	Function *RuleMacaddr2;
	Function *RuleMacType;
	Function *RuleFrag;
	Function *RuleIn;
	Function *RuleLayer2;
	Function *RuleDiverted;
	Function *RuleProto;
	Function *RuleIpSrc;
	Function *RuleIpDstLookup;
	Function *RuleIpDstMask;
	Function *RuleIpSrcMe;
#ifdef INET6
	Function *RuleIp6SrcMe;
#endif /* INET6 */
	Function *RuleIpSrcSet;
	Function *RuleIpDst;
	Function *RuleIpDstMe;
#ifdef INET6
	Function *RuleIp6DstMe;
#endif /* INET6 */
	Function *RuleIpDstport;
	Function *RuleIcmptype;
#ifdef INET6
	Function *RuleIcmp6type;
#endif /* INET6 */
	Function *RuleIpopt;
	Function *RuleIpver;
	Function *RuleIpttl;
	Function *RuleIpprecedence;
	Function *RuleIptos;
	Function *RuleDscp;
	Function *RuleTcpdatalen;
	Function *RuleTcpflags;
	Function *RuleTcpopts;
	Function *RuleTcpseq;
	Function *RuleTcpack;
	Function *RuleTcpwin;
	Function *RuleEstab;
	Function *RuleAltq;
	Function *RuleLog;
	Function *RuleProb;
	Function *RuleVerrevpath;
	Function *RuleVersrcreach;
	Function *RuleAntispoof;
#ifdef IPSEC
		Function *RuleIpsec;
#endif
#ifdef INET6
		Function *RuleIp6Src;
		Function *RuleIp6Dst;
		Function *RuleIp6DstMask;
		Function *RuleFlow6id;
		Function *RuleExtHdr;
		Function *RuleIp6;
#endif /* INET6 */
	Function *RuleIp4;
	Function *RuleTag;
	Function *RuleFib;
	Function *RuleSockarg;
	Function *RuleTagged;
	Function *RuleKeepState;
	Function *RuleCheckState;
	Function *RuleAccept;
	Function *RuleQueue;
	Function *RuleTee;
	Function *RuleCount;
	Function *RuleSkipto;
	Function *RuleCallreturn;
	Function *RuleReject;
#ifdef INET6
		Function *RuleUnreach6;
#endif /* INET6 */
	Function *RuleDeny;
	Function *RuleForwardIp;
#ifdef INET6
	Function *RuleForwardIp6;
#endif /* INET6 */
	Function *RuleNgtee;
	Function *RuleSetfib;
	Function *RuleSetdscp;
	Function *RuleNat;
	Function *RuleReass;

	// Used structs.
	StructType *IfnetTy;
	StructType *InAddrTy;
	StructType *IpTy;
	StructType *IpFwArgsTy;
	StructType *IpFwChainTy;
	StructType *IpFwTy;
	StructType *IpfwInsnTy;
	StructType *IpfwInsnU16Ty;
	StructType *IpfwInsnIpTy;
	StructType *IpfwDynRuleTy;
	StructType *IpfwInsnIfTy;
	StructType *MbufTy;
	StructType *UcredTy;

	// Pointer to structs type.
	PointerType *IfnetPtrTy;
	PointerType *InAddrPtrTy;
	PointerType *IpPtrTy;
	PointerType *IpFwArgsPtrTy;
	PointerType *IpFwChainPtrTy;
	PointerType *IpFwPtrTy;
	PointerType *IpfwInsnPtrTy;
	PointerType *IpfwInsnU16PtrTy;
	PointerType *IpfwInsnIpPtrTy;
	PointerType *IpfwDynRulePtrTy;
	PointerType *IpfwInsnIfPtrTy;
	PointerType *MbufPtrTy;
	PointerType *UcredPtrTy;

	// Load the bc for JIT compilation.
	Module *
	loadBitcode(std::string name)
	{
		auto buff = MemoryBuffer::getFile(name);
		if (buff.getError()){
			std::cerr << "Failed to open bitcode: " << buff.getError() << "\n";
			return (NULL);
		}

		auto modptr = parseBitcodeFile(buff.get().get(), Con);
		if ((modptr.getError())){
			std::cerr << "Failed to parse bitcode: " << buff.getError() << "\n";
			return (NULL);
		}
		return (modptr.get());
	}

	BasicBlock*
	nextRule()
	{
		int nextn = rulenumber + 1;
		if (nextn >= rules.size())
			return (End);
		else
			return (rules[nextn]);
	}

	// Create the needed variables to perform pkt filtering.
	void
	setEnv()
	{
		// Get function arguments.
		// (struct ip_fw_args *, struct ip_fw_chain *)
		auto& arglist = Func->getArgumentList();

		// Error
		if (arglist.size() != 2)
			err(1, "Compilation error: no correct parameters\n");

		Args = &arglist.front();
		Chain = &arglist.back();

		// Get Type objects
		Int8Ty = Type::getInt8Ty(Con);
		Int16Ty = Type::getInt16Ty(Con);
		Int32Ty = Type::getInt32Ty(Con);
		Int64Ty = Type::getInt64Ty(Con);
		Int8PtrTy = PointerType::getUnqual(Int8Ty);
		Int16PtrTy = PointerType::getUnqual(Int16Ty);

		// Get StrucType from bitcode.
		MbufTy = mod->getTypeByName("struct.mbuf");
		if (MbufTy == NULL)
			err(1, "bitcode fault: struct.mbuf");
		IfnetTy = mod->getTypeByName("struct.ifnet");
		if (IfnetTy == NULL)
			err(1, "bitcode fault: struct.ifnet");
		InAddrTy = mod->getTypeByName("struct.in_addr");
		if (InAddrTy == NULL)
			err(1, "bitcode fault: struct.in_addr");
		IpTy = mod->getTypeByName("struct.ip");
		if (IpTy == NULL)
			err(1, "bitcode fault: struct.ip");
		IpFwArgsTy = mod->getTypeByName("struct.ip_fw_args");
		if (IpFwArgsTy == NULL)
			err(1, "bitcode fault: struct.ip_fw_args");
		IpFwChainTy = mod->getTypeByName("struct.ip_fw_chain");
		if (IpFwChainTy == NULL)
			err(1, "bitcode fault: struct.ip_fw_chain");
		IpFwTy = mod->getTypeByName("struct.ip_fw");
		if (IpFwTy == NULL)
			err(1, "bitcode fault: struct.ip_fw");
		IpfwInsnTy = mod->getTypeByName("struct._ipfw_insn");
		if (IpfwInsnTy == NULL)
			err(1, "bitcode fault: struct._ipfw_insn");
		IpfwInsnU16Ty = mod->getTypeByName("struct._ipfw_insn_u16");
		if (IpfwInsnU16Ty == NULL)
			err(1, "bitcode fault: struct._ipfw_insn_u16");
		IpfwInsnIpTy = mod->getTypeByName("struct._ipfw_insn_ip");
		if (IpfwInsnIpTy == NULL)
			err(1, "bitcode fault: struct._ipfw_insn_ip");
		IpfwInsnIfTy = mod->getTypeByName("struct._ipfw_insn_if");
		if (IpfwInsnIfTy == NULL)
			err(1, "bitcode fault: struct._ipfw_insn_if");
		IpfwDynRuleTy = mod->getTypeByName("struct._ipfw_dyn_rule");
		if (IpfwDynRuleTy == NULL)
			err(1, "bitcode fault: struct._ipfw_dyn_rule");

		// Create Pointer to StructType types.
		MbufPtrTy = PointerType::getUnqual(MbufTy);
		IfnetPtrTy = PointerType::getUnqual(IfnetTy);
		InAddrPtrTy = PointerType::getUnqual(InAddrTy);
		IpPtrTy = PointerType::getUnqual(IpTy);
		IpFwArgsPtrTy = PointerType::getUnqual(IpFwArgsTy);
		IpFwChainPtrTy = PointerType::getUnqual(IpFwChainTy);
		IpFwPtrTy = PointerType::getUnqual(IpFwTy);
		IpfwInsnPtrTy = PointerType::getUnqual(IpfwInsnTy);
		IpfwInsnU16PtrTy = PointerType::getUnqual(IpfwInsnU16Ty);
		IpfwInsnIpPtrTy = PointerType::getUnqual(IpfwInsnIpTy);
		IpfwInsnIfPtrTy = PointerType::getUnqual(IpfwInsnIfTy);
		IpfwDynRulePtrTy = PointerType::getUnqual(IpfwDynRuleTy);

		// Get Function defs from bitcode.
		// All of them are auxiliary functions.
		InspectPkt = mod->getFunction("inspect_pkt");
		if (InspectPkt == NULL)
			err(1, "bitcode fault: inspect_pkt");
		IsIcmpQuery = mod->getFunction("is_icmp_query");
		if (IsIcmpQuery == NULL)
			err(1, "bitcode fault: is_icmp_query");
		FlagsMatch = mod->getFunction("flags_match");
		if (FlagsMatch == NULL)
			err(1, "bitcode fault: flags_match");
		IpoptsMatch = mod->getFunction("ipopts_match");
		if (IpoptsMatch == NULL)
			err(1, "bitcode fault: ipopts_match");
		TcpoptsMatch = mod->getFunction("tcpopts_match");
		if (TcpoptsMatch == NULL)
			err(1, "bitcode fault: tcpopts_match");
		IfaceMatch = mod->getFunction("iface_match");
		if (IfaceMatch == NULL)
			err(1, "bitcode fault: iface_match");
		VerifyPath = mod->getFunction("verify_path");
		if (VerifyPath == NULL)
			err(1, "bitcode fault: verify_path");

#ifdef INET6
		Icmp6typeMatch = mod->getFunction("icmp6type_match");
		if (Icmp6typeMatch == NULL)
			err(1, "bitcode fault: icmp6type_match");
		SearchIp6AddrNet = mod->getFunction("search_ip6_addr_net");
		if (SearchIp6AddrNet == NULL)
			err(1, "bitcode fault: search_ip6_addr_net");
		Flow6idMatch = mod->getFunction("flow6id_match");
		if (Flow6idMatch == NULL)
			err(1, "bitcode fault: flow6id_match");
		VerifyPath6 = mod->getFunction("verify_path6");
		if (VerifyPath6 == NULL)
			err(1, "bitcode fault: verify_path6");
		IsIcmp6Query = mod->getFunction("is_icmp6_query");
		if (IsIcmp6Query == NULL)
			err(1, "bitcode fault: is_icmp6_query");
		SendReject6 = mod->getFunction("send_reject6");
		if (SendReject6 == NULL)
			err(1, "bitcode fault: send_reject6");
#endif /* INET6 */

		SendReject = mod->getFunction("send_reject");
		if (SendReject == NULL)
			err(1, "bitcode fault: send_reject");
		SetMatch = mod->getFunction("set_match");
		if (SetMatch == NULL)
			err(1, "bitcode fault: set_match");
		JumpFast = mod->getFunction("jump_fast");
		if (JumpFast == NULL)
			err(1, "bitcode fault: jump_fast");

		// Functions declared at bitcode.
		PrintfFunc = mod->getFunction("printf");
		if (PrintfFunc == NULL)
			err(1, "bitcode fault: printf");
		IpfwFindRule = mod->getFunction("ipfw_find_rule");
		if (IpfwFindRule == NULL)
			err(1, "bitcode fault: ipfw_find_rule");

		// Load the rules
		RuleNop = mod->getFunction("rule_nop");
		if (RuleNop  == NULL)
			err(1, "bitcode fault: RuleNop ");
		RuleForwardMac = mod->getFunction("rule_forward_mac");
		if (RuleForwardMac  == NULL)
			err(1, "bitcode fault: RuleForwardMac ");
		RuleJail = mod->getFunction("rule_jail");
		if (RuleJail  == NULL)
			err(1, "bitcode fault: RuleJail ");
		RuleRecv = mod->getFunction("rule_recv");
		if (RuleRecv  == NULL)
			err(1, "bitcode fault: RuleRecv ");
		RuleXmit = mod->getFunction("rule_xmit");
		if (RuleXmit  == NULL)
			err(1, "bitcode fault: RuleXmit ");
		RuleVia = mod->getFunction("rule_via");
		if (RuleVia  == NULL)
			err(1, "bitcode fault: RuleVia ");
		RuleMacaddr2 = mod->getFunction("rule_macaddr2");
		if (RuleMacaddr2  == NULL)
			err(1, "bitcode fault: RuleMacaddr2 ");
		RuleMacType = mod->getFunction("rule_mac_type");
		if (RuleMacType  == NULL)
			err(1, "bitcode fault: RuleMacType ");
		RuleFrag = mod->getFunction("rule_frag");
		if (RuleFrag  == NULL)
			err(1, "bitcode fault: RuleFrag ");
		RuleIn = mod->getFunction("rule_in");
		if (RuleIn  == NULL)
			err(1, "bitcode fault: RuleIn ");
		RuleLayer2 = mod->getFunction("rule_layer2");
		if (RuleLayer2  == NULL)
			err(1, "bitcode fault: RuleLayer2 ");
		RuleDiverted = mod->getFunction("rule_diverted");
		if (RuleDiverted  == NULL)
			err(1, "bitcode fault: RuleDiverted ");
		RuleProto = mod->getFunction("rule_proto");
		if (RuleProto  == NULL)
			err(1, "bitcode fault: RuleProto ");
		RuleIpSrc = mod->getFunction("rule_ip_src");
		if (RuleIpSrc  == NULL)
			err(1, "bitcode fault: RuleIpSrc ");
		RuleIpDstLookup = mod->getFunction("rule_ip_dst_lookup");
		if (RuleIpDstLookup  == NULL)
			err(1, "bitcode fault: RuleIpDstLookup ");
		RuleIpDstMask = mod->getFunction("rule_ip_dst_mask");
		if (RuleIpDstMask  == NULL)
			err(1, "bitcode fault: RuleIpDstMask ");
		RuleIpSrcMe = mod->getFunction("rule_ip_src_me");
		if (RuleIpSrcMe  == NULL)
			err(1, "bitcode fault: RuleIpSrcMe ");

#ifdef INET6
		RuleIp6SrcMe = mod->getFunction("rule_ip6_src_me");
		if (RuleIp6SrcMe  == NULL)
			err(1, "bitcode fault: RuleIp6SrcMe ");
#endif /* INET6 */

		RuleIpSrcSet = mod->getFunction("rule_ip_src_set");
		if (RuleIpSrcSet  == NULL)
			err(1, "bitcode fault: RuleIpSrcSet ");
		RuleIpDst = mod->getFunction("rule_ip_dst");
		if (RuleIpDst  == NULL)
			err(1, "bitcode fault: RuleIpDst ");
		RuleIpDstMe = mod->getFunction("rule_ip_dst_me");
		if (RuleIpDstMe  == NULL)
			err(1, "bitcode fault: RuleIpDstMe ");

#ifdef INET6
		RuleIp6DstMe = mod->getFunction("rule_ip6_dst_me");
		if (RuleIp6DstMe  == NULL)
			err(1, "bitcode fault: RuleIp6DstMe ");
#endif /* INET6 */

		RuleIpDstport = mod->getFunction("rule_ip_dstport");
		if (RuleIpDstport  == NULL)
			err(1, "bitcode fault: RuleIpDstport ");
		RuleIcmptype = mod->getFunction("rule_icmptype");
		if (RuleIcmptype  == NULL)
			err(1, "bitcode fault: RuleIcmptype ");

#ifdef INET6
		RuleIcmp6type = mod->getFunction("rule_icmp6type");
		if (RuleIcmp6type  == NULL)
			err(1, "bitcode fault: RuleIcmp6type ");
#endif /* INET6 */

		RuleIpopt = mod->getFunction("rule_ipopt");
		if (RuleIpopt  == NULL)
			err(1, "bitcode fault: RuleIpopt ");
		RuleIpver = mod->getFunction("rule_ipver");
		if (RuleIpver  == NULL)
			err(1, "bitcode fault: RuleIpver ");
		RuleIpttl = mod->getFunction("rule_ipttl");
		if (RuleIpttl  == NULL)
			err(1, "bitcode fault: RuleIpttl ");
		RuleIpprecedence = mod->getFunction("rule_ipprecedence");
		if (RuleIpprecedence  == NULL)
			err(1, "bitcode fault: RuleIpprecedence ");
		RuleIptos = mod->getFunction("rule_iptos");
		if (RuleIptos  == NULL)
			err(1, "bitcode fault: RuleIptos ");
		RuleDscp = mod->getFunction("rule_dscp");
		if (RuleDscp  == NULL)
			err(1, "bitcode fault: RuleDscp ");
		RuleTcpdatalen = mod->getFunction("rule_tcpdatalen");
		if (RuleTcpdatalen  == NULL)
			err(1, "bitcode fault: RuleTcpdatalen ");
		RuleTcpflags = mod->getFunction("rule_tcpflags");
		if (RuleTcpflags  == NULL)
			err(1, "bitcode fault: RuleTcpflags ");
		RuleTcpopts = mod->getFunction("rule_tcpopts");
		if (RuleTcpopts  == NULL)
			err(1, "bitcode fault: RuleTcpopts ");
		RuleTcpseq = mod->getFunction("rule_tcpseq");
		if (RuleTcpseq  == NULL)
			err(1, "bitcode fault: RuleTcpseq ");
		RuleTcpack = mod->getFunction("rule_tcpack");
		if (RuleTcpack  == NULL)
			err(1, "bitcode fault: RuleTcpack ");
		RuleTcpwin = mod->getFunction("rule_tcpwin");
		if (RuleTcpwin  == NULL)
			err(1, "bitcode fault: RuleTcpwin ");
		RuleEstab = mod->getFunction("rule_estab");
		if (RuleEstab  == NULL)
			err(1, "bitcode fault: RuleEstab ");
		RuleAltq = mod->getFunction("rule_altq");
		if (RuleAltq  == NULL)
			err(1, "bitcode fault: RuleAltq ");
		RuleLog = mod->getFunction("rule_log");
		if (RuleLog  == NULL)
			err(1, "bitcode fault: RuleLog ");
		RuleProb = mod->getFunction("rule_prob");
		if (RuleProb  == NULL)
			err(1, "bitcode fault: RuleProb ");
		RuleVerrevpath = mod->getFunction("rule_verrevpath");
		if (RuleVerrevpath  == NULL)
			err(1, "bitcode fault: RuleVerrevpath ");
		RuleVersrcreach = mod->getFunction("rule_versrcreach");
		if (RuleVersrcreach  == NULL)
			err(1, "bitcode fault: RuleVersrcreach ");
		RuleAntispoof = mod->getFunction("rule_antispoof");
		if (RuleAntispoof  == NULL)
			err(1, "bitcode fault: RuleAntispoof ");

#ifdef IPSEC
		RuleIpsec = mod->getFunction("rule_ipsec");
		if (RuleIpsec  == NULL)
			err(1, "bitcode fault: RuleIpsec ");
#endif

#ifdef INET6
		RuleIp6Src = mod->getFunction("rule_ip6_src");
		if (RuleIp6Src  == NULL)
			err(1, "bitcode fault: RuleIp6Src ");
		RuleIp6Dst = mod->getFunction("rule_ip6_dst");
		if (RuleIp6Dst  == NULL)
			err(1, "bitcode fault: RuleIp6Dst ");
		RuleIp6DstMask = mod->getFunction("rule_ip6_dst_mask");
		if (RuleIp6DstMask  == NULL)
			err(1, "bitcode fault: RuleIp6DstMask ");
		RuleFlow6id = mod->getFunction("rule_flow6id");
		if (RuleFlow6id  == NULL)
			err(1, "bitcode fault: RuleFlow6id ");
		RuleExtHdr = mod->getFunction("rule_ext_hdr");
		if (RuleExtHdr  == NULL)
			err(1, "bitcode fault: RuleExtHdr ");
		RuleIp6 = mod->getFunction("rule_ip6");
		if (RuleIp6  == NULL)
			err(1, "bitcode fault: RuleIp6 ");
#endif /* INET6 */

		RuleIp4 = mod->getFunction("rule_ip4");
		if (RuleIp4  == NULL)
			err(1, "bitcode fault: RuleIp4 ");
		RuleTag = mod->getFunction("rule_tag");
		if (RuleTag  == NULL)
			err(1, "bitcode fault: RuleTag ");
		RuleFib = mod->getFunction("rule_fib");
		if (RuleFib  == NULL)
			err(1, "bitcode fault: RuleFib ");
		RuleSockarg = mod->getFunction("rule_sockarg");
		if (RuleSockarg  == NULL)
			err(1, "bitcode fault: RuleSockarg ");
		RuleTagged = mod->getFunction("rule_tagged");
		if (RuleTagged  == NULL)
			err(1, "bitcode fault: RuleTagged ");
		RuleKeepState = mod->getFunction("rule_keep_state");
		if (RuleKeepState  == NULL)
			err(1, "bitcode fault: RuleKeepState ");
		RuleCheckState = mod->getFunction("rule_check_state");
		if (RuleCheckState  == NULL)
			err(1, "bitcode fault: RuleCheckState ");
		RuleAccept = mod->getFunction("rule_accept");
		if (RuleAccept  == NULL)
			err(1, "bitcode fault: RuleAccept ");
		RuleQueue = mod->getFunction("rule_queue");
		if (RuleQueue  == NULL)
			err(1, "bitcode fault: RuleQueue ");
		RuleTee = mod->getFunction("rule_tee");
		if (RuleTee  == NULL)
			err(1, "bitcode fault: RuleTee ");
		RuleCount = mod->getFunction("rule_count");
		if (RuleCount  == NULL)
			err(1, "bitcode fault: RuleCount ");
		RuleSkipto = mod->getFunction("rule_skipto");
		if (RuleSkipto  == NULL)
			err(1, "bitcode fault: RuleSkipto ");
		RuleCallreturn = mod->getFunction("rule_callreturn");
		if (RuleCallreturn  == NULL)
			err(1, "bitcode fault: RuleCallreturn ");
		RuleReject = mod->getFunction("rule_reject");
		if (RuleReject  == NULL)
			err(1, "bitcode fault: RuleReject ");

#ifdef INET6
		RuleUnreach6 = mod->getFunction("rule_unreach6");
		if (RuleUnreach6  == NULL)
			err(1, "bitcode fault: RuleUnreach6 ");
#endif /* INET6 */

		RuleDeny = mod->getFunction("rule_deny");
		if (RuleDeny  == NULL)
			err(1, "bitcode fault: RuleDeny ");
		RuleForwardIp = mod->getFunction("rule_forward_ip");
		if (RuleForwardIp  == NULL)
			err(1, "bitcode fault: RuleForwardIp ");

#ifdef INET6
		RuleForwardIp6 = mod->getFunction("rule_forward_ip6");
		if (RuleForwardIp6  == NULL)
			err(1, "bitcode fault: RuleForwardIp6 ");
#endif /* INET6 */

		RuleNgtee = mod->getFunction("rule_ngtee");
		if (RuleNgtee  == NULL)
			err(1, "bitcode fault: RuleNgtee ");
		RuleSetfib = mod->getFunction("rule_setfib");
		if (RuleSetfib  == NULL)
			err(1, "bitcode fault: RuleSetfib ");
		RuleSetdscp = mod->getFunction("rule_setdscp");
		if (RuleSetdscp  == NULL)
			err(1, "bitcode fault: RuleSetdscp ");
		RuleNat = mod->getFunction("rule_nat");
		if (RuleNat  == NULL)
			err(1, "bitcode fault: RuleNat ");
		RuleReass = mod->getFunction("rule_reass");
		if (RuleReass  == NULL)
			err(1, "bitcode fault: RuleReass ");
	}

	// Allocate and initialize LLVM vars.
	// It creates a call to the pkt inspection function.
	// Note: The type of the object returned by CreateStore
	// is already a pointer to a given type.
	void
	allocaAndInit()
	{
		Irb.SetInsertPoint(Entry);

		// Control flow variables.
		Done = Irb.CreateAlloca(Int32Ty, nullptr, "done");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Done);

		FPos = Irb.CreateAlloca(Int32Ty, nullptr, "fpos");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), FPos);

		Retval = Irb.CreateAlloca(Int32Ty, nullptr, "retval");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Retval);

		// m = args->m (idx: 0)
		MPtr = Irb.CreateAlloca(MbufPtrTy, nullptr, "m");
		Irb.CreateStore(Irb.CreateLoad(Irb.CreateStructGEP(Args, 0)), MPtr);
		M = Irb.CreateLoad(MPtr);

		// ip = (struct ip *)((m)->m_data) (idx: 2)
		IpPtr = Irb.CreateAlloca(IpPtrTy, nullptr, "ip");
		Value *M_data = Irb.CreateStructGEP(M, 2);
		Value *M_casted = Irb.CreateBitCast(M_data, IpPtrTy);
		Irb.CreateStore(M_casted, IpPtr);

		UcredLookup = Irb.CreateAlloca(Int32Ty, nullptr, "ucred_lookup");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), UcredLookup);

		Oif = Irb.CreateAlloca(IfnetTy, nullptr, "oif"); // Init: args->oif
		Irb.CreateLoad(Irb.CreateStructGEP(Args, 1), Oif);

		Hlen = Irb.CreateAlloca(Int32Ty, nullptr, "hlen");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Hlen);

		Offset = Irb.CreateAlloca(Int16Ty, nullptr, "offset");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), Offset);

		Ip6fMf = Irb.CreateAlloca(Int16Ty, nullptr, "ip6f_mf");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), Ip6fMf);

		// proto = 0
		Proto = Irb.CreateAlloca(Int8Ty, nullptr, "proto");
		Irb.CreateStore(ConstantInt::get(Int8Ty, 0), Proto);
		// args->f_id.proto = 0 (idx: 6, 5)
		Value *F_id = Irb.CreateStructGEP(Args, 6);
		Value *FProto = Irb.CreateStructGEP(F_id, 5);
		Irb.CreateStore(ConstantInt::get(Int8Ty, 0), FProto);

		SrcPort = Irb.CreateAlloca(Int16Ty, nullptr, "src_port");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), SrcPort);
		DstPort = Irb.CreateAlloca(Int16Ty, nullptr, "dst_port");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), DstPort);

		//src_ip.s_addr = 0;
		SrcIp = Irb.CreateAlloca(InAddrTy, nullptr, "src_ip");
		Value *Src_s_addr = Irb.CreateStructGEP(SrcIp, 0);
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Src_s_addr);
		//dst_ip.s_addr = 0;
		DstIp = Irb.CreateAlloca(InAddrTy, nullptr, "dst_ip");
		Value *Dst_s_addr = Irb.CreateStructGEP(DstIp, 0);
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Dst_s_addr);

		//iplen = 0;
		Iplen = Irb.CreateAlloca(Int16Ty, nullptr, "iplen");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), Iplen);

		// pktlen = m->m_pkthdr.len;
		// m_pkthdr is the 6th element (idx: 5)
		// len is the 2nd element (idx: 1)
		Pktlen = Irb.CreateAlloca(Int32Ty, nullptr, "pktlen");
		Value *Header = Irb.CreateStructGEP(M, 5);
		Value *LengthPtr = Irb.CreateStructGEP(Header, 1);
		Value *Length = Irb.CreateLoad(LengthPtr);
		Irb.CreateStore(Length, Pktlen);

		Etype = Irb.CreateAlloca(Int16Ty, nullptr, "etype");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), Etype);

		DynDir = Irb.CreateAlloca(Int32Ty, nullptr, "dyn_dir");
		Irb.CreateStore(ConstantInt::get(Int32Ty, MATCH_UNKNOWN), DynDir);

		Q = Irb.CreateAlloca(IpfwDynRulePtrTy, nullptr, "q");
		Irb.CreateStore(ConstantPointerNull::get(IpfwDynRulePtrTy), Q);

		// There are no (void *), we use i8*
		Ulp = Irb.CreateAlloca(Int8PtrTy, nullptr, "ulp");
		Irb.CreateStore(ConstantPointerNull::get(Int8PtrTy), Ulp);

		IsIpv4 = Irb.CreateAlloca(Int32Ty, nullptr, "is_ipv4");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), IsIpv4);
		IsIpv6 = Irb.CreateAlloca(Int32Ty, nullptr, "is_ipv6");
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), IsIpv6);
		Icmp6Type = Irb.CreateAlloca(Int8Ty, nullptr, "icmp6_type");
		Irb.CreateStore(ConstantInt::get(Int8Ty, 0), Icmp6Type);
		ExtHd = Irb.CreateAlloca(Int16Ty, nullptr, "ext_hd");
		Irb.CreateStore(ConstantInt::get(Int16Ty, 0), ExtHd);

		// If it returns one, goto pullup_failed.
		// Else, goto first rule.
		Value *Ip = Irb.CreateLoad(IpPtr);
		Value *UlpL = Irb.CreateLoad(Ulp);

		// inspect_pkt(struct ip_fw_args *args, struct ip *ip, struct mbuf *m, struct in_addr *src_ip, struct in_addr *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint16_t *etype, uint16_t *ext_hd, uint16_t *iplen, int *pktlen, int *is_ipv4, int *is_ipv6, u_int *hlen, uint8_t *proto, uint8_t *icmp6_type, u_short *ip6f_mf, u_short *offset, void *ulp)
		Value *InspectPktCall = Irb.CreateCall(InspectPkt, {Args, Ip, M, SrcIp, 
			DstIp, SrcPort, DstPort, Etype, ExtHd, Iplen, Pktlen, IsIpv4,
			IsIpv6, Hlen, Proto, Icmp6Type, Ip6fMf, Offset, UlpL});

		Value *Comp = Irb.CreateICmpEQ(InspectPktCall, ConstantInt::get(Int32Ty, 1));
		Irb.CreateCondBr(Comp, PullupFailed, CheckTag);
	}

	// This is equivalent to the pullup_failed tag.
	void
	emit_pullup_failed()
	{
		BasicBlock *print = BasicBlock::Create(Con, "print", Func);
		BasicBlock *ret = BasicBlock::Create(Con, "ret", Func);

		Value *Is_verbose, *Str, *Comp;

		// VNET_DECLARE(int, fw_verbose);
		// #define	V_fw_verbose		VNET(fw_verbose)
		// We should be fine getting that from the Module.

		// pullup_failed:
		// 	if (V_fw_verbose)
		// 		printf("ipfw: pullup failed\n");
		// 	return (IP_FW_DENY);

		Is_verbose = mod->getGlobalVariable("fw_verbose");
		Str = Irb.CreateGlobalString("ipfw: pullup failed\n");

		Irb.SetInsertPoint(PullupFailed);

		// if (V_fw_verbose)
		Value *Is_verboseL = Irb.CreateLoad(Is_verbose); 
		Comp = Irb.CreateICmpEQ(Is_verboseL, ConstantInt::get(Int32Ty, 0));
		Irb.CreateCondBr(Comp, ret, print);

		// printf("ipfw: pullup failed\n");
		Irb.SetInsertPoint(print);
		Value *StrFirstElement = Irb.CreateStructGEP(Str, 0);
		Irb.CreateCall(PrintfFunc, StrFirstElement);
		Irb.CreateBr(ret);

		// return (IP_FW_DENY);
		Irb.SetInsertPoint(ret);
		Irb.CreateRet(ConstantInt::get(Int32Ty, IP_FW_DENY));
	}

	void
	emit_check_tag()
	{
		BasicBlock *Tagged = BasicBlock::Create(Con, "tagged", Func);
		BasicBlock *Nottagged = BasicBlock::Create(Con, "nottagged", Func);
		BasicBlock *Jt = BasicBlock::Create(Con, "jt", Func);
		BasicBlock *Jf = BasicBlock::Create(Con, "jf", Func);

		Value *Comp;

		Irb.SetInsertPoint(CheckTag);

		// if (args->rule.slot) {
		// 	/*
		// 	 * Packet has already been tagged as a result of a previous
		// 	 * match on rule args->rule aka args->rule_id (PIPE, QUEUE,
		// 	 * REASS, NETGRAPH, DIVERT/TEE...)
		// 	 * Validate the slot and continue from the next one
		// 	 * if still present, otherwise perform a lookup.
		// 	 */
		// 	f_pos = (args->rule.chain_id == chain->id) ?
		// 		args->rule.slot :
		// 		ipfw_find_rule(chain, args->rule.rulenum,
		// 		args->rule.rule_id);
		// } else {
		// 	f_pos = 0;
		// }

		// if (args->rule.slot)
		Value *Rule = Irb.CreateStructGEP(Args, 4);
		Value *Slot = Irb.CreateStructGEP(Rule, 0);
		Value *SlotValue = Irb.CreateLoad(Slot);
		Comp = Irb.CreateICmpEQ(SlotValue, ConstantInt::get(Int32Ty, 0));
		Irb.CreateCondBr(Comp, Nottagged, Tagged);

		Irb.SetInsertPoint(Tagged);
		// if (args->rule.chain_id == chain->id)
		Value *ChainId = Irb.CreateStructGEP(Rule, 3); 
		Value *Id = Irb.CreateStructGEP(Chain, 12);
		Value *ChainIdL = Irb.CreateLoad(ChainId);
		Value *IdL = Irb.CreateLoad(Id);
		Comp = Irb.CreateICmpEQ(ChainIdL, IdL);
		Irb.CreateCondBr(Comp, Jt, Jf);

		// f_pos = args->rule.slot;
		Irb.SetInsertPoint(Jt);
		Irb.CreateStore(SlotValue, FPos);
		Irb.CreateBr(Nottagged);

		// else fpos = ipfw_find_rule(chain, args->rule.rulenum, args->rule.rule_id)
		Irb.SetInsertPoint(Jf);
		Value *Rulenum = Irb.CreateStructGEP(Rule, 1);
		Value *RulenumL = Irb.CreateLoad(Rulenum);
		Value *RuleId = Irb.CreateStructGEP(Rule, 2);
		Value *RuleIdL = Irb.CreateLoad(RuleId);
		Value *FindRuleCall = Irb.CreateCall3(IpfwFindRule, Chain, RulenumL, RuleIdL);
		Irb.CreateStore(FindRuleCall, FPos);

		// Branch to Nottagged because it
		// only finishes the entry BasicBlock.
		Irb.CreateBr(Nottagged);

		// else f_pos = 0;
		// Since f_pos is initialized by default as 0, we only br.
		Irb.SetInsertPoint(Nottagged);
		Irb.CreateBr(rules.front());
	}

	public:
	ipfwJIT(int rulesnumber) : Con(getGlobalContext()), Irb(Con)
	{
		// Create the module and load the code.
		mod = loadBitcode("rules.bc");

		Func = mod->getFunction("ipfw_chk_jit");
		if (Func == NULL)
			err(1, "bitcode fault: ipfw_chk_jit");

		Func->setLinkage(GlobalValue::ExternalLinkage);

		// Create static BasicBlocks.
		// The entry basic block contains all the initialization 
		// and allocation of resources, and a basic check done 
		// before start emmiting the rules code.
		Entry = BasicBlock::Create(Con, "Entry", Func);
		End = BasicBlock::Create(Con, "End", Func);
		CheckTag = BasicBlock::Create(Con, "CheckTag", Func);
		PullupFailed = BasicBlock::Create(Con, "PullupFailed", Func);

		// Get struct types, and store vars
		setEnv();

		// Start compilation
		allocaAndInit();

		// Initialize the vector.
		rules = std::vector<BasicBlock *>(rulesnumber);
		for (auto &i: rules){
			i = BasicBlock::Create(Con, "rule", Func);
		}

		emit_check_tag();
		emit_pullup_failed();
	}

	funcptr
	compile()
	{
		InitializeNativeTarget();
		LLVMLinkInJIT();

		// Dump it?
		//mod->dump();
		//Func->dump();

		// Optimise
		PassManagerBuilder PMBuilder;
		PMBuilder.OptLevel = 3;
		//PMBuilder.Inliner = createFunctionInliningPass(275);

		// Function passes
		FunctionPassManager *PerFunctionPasses = new FunctionPassManager(mod);
		PMBuilder.populateFunctionPassManager(*PerFunctionPasses);
		PerFunctionPasses->run(*Func);
		PerFunctionPasses->doFinalization();
		delete PerFunctionPasses;

		// We only used the function to get symbols.
		Function *vf = mod->getFunction("voidfunction");
		vf->eraseFromParent();

		//Compile
		std::string errstr;
		EngineBuilder EB = EngineBuilder(std::move(mod));
		ExecutionEngine *EE = EB.setEngineKind(EngineKind::JIT)
			//.setUseMCJIT(true)
			.setOptLevel(CodeGenOpt::Level::Aggressive)
			.setVerifyModules(true)
			.setErrorStr(&errstr)
			.create();

		if (!EE) {
			fprintf(stderr, "Compilation error: %s\n", errstr.c_str());
			exit(1);
		}

		return (funcptr)EE->getPointerToFunction(Func);
	}

	// Function used to help when checking the type of the function calls.
	void dumpCall(Function *F, std::vector<Value*> args)
	{
		std::cout << std::endl;
		F->getType()->dump();
		std::cout << std::endl;
		for (Value * v : args) {
			v->dump();
		}
		std::cout << std::endl;
		Irb.CreateCall(F, args);
		return;
	}

	void
	end_rule()
	{
		rulenumber++;
	}

	void
	emit_outer_for_prologue()
	{
		BasicBlock *jt = BasicBlock::Create(Con, "jt", Func);
		BasicBlock *jf = BasicBlock::Create(Con, "jf", Func);

		Value *SetDisable = mod->getGlobalVariable("set_disable");

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
		Cmd = Irb.CreateAlloca(IpfwInsnPtrTy, nullptr, "cmd");
		Tablearg = Irb.CreateAlloca(Int32Ty, nullptr, "tablearg");
		L = Irb.CreateAlloca(Int32Ty, nullptr, "l");
		Cmdlen = Irb.CreateAlloca(Int32Ty, nullptr, "cmdlen");
		SkipOr = Irb.CreateAlloca(Int32Ty, nullptr, "skipor");
		// struct ip_fw *f;
		F = Irb.CreateAlloca(IpFwPtrTy, nullptr, "f");

		// uInt32_t tablearg = 0;
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Tablearg);

		// f = chain->map[f_pos]; idxs: 5, f_pos
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *ExtFPos = Irb.CreateSExt(FPosL, Int64Ty);
		Value *Map = Irb.CreateStructGEP(Chain, 5);
		Value *MapL = Irb.CreateLoad(Map);
		Value *MapFPos = Irb.CreateInBoundsGEP(MapL, ExtFPos);
		Value *MapFPosL = Irb.CreateLoad(MapFPos);
		Irb.CreateStore(MapFPosL, F);

		// if (V_set_disable & (1 << f->set) )
		Value *FL = Irb.CreateLoad(F);
		Value *Set = Irb.CreateStructGEP(FL, 5);
		Value *SetL = Irb.CreateLoad(Set); //uint8
		Value *ShiftedSet = Irb.CreateShl(ConstantInt::get(Int8Ty, 1), SetL);
		Value *SetDisableL = Irb.CreateLoad(SetDisable);
		Value *ShiftedSet32 = Irb.CreateZExt(ShiftedSet, Int32Ty);
		Value *AndOp = Irb.CreateAnd(SetDisableL, ShiftedSet32);
		Value *Comp = Irb.CreateICmpNE(AndOp, ConstantInt::get(Int32Ty, 0));
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
		BasicBlock *firstt = BasicBlock::Create(Con, "firstt", Func);
		BasicBlock *firstf = BasicBlock::Create(Con, "firstf", Func);
		BasicBlock *secondt = BasicBlock::Create(Con, "secondt", Func);
		BasicBlock *secondf = BasicBlock::Create(Con, "secondf", Func);

		Value *Comp, *AndOp;

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
		Value *FL = Irb.CreateLoad(F);
		Value *FCmdlen = Irb.CreateStructGEP(FL, 3);
		Value *FCmdlenL = Irb.CreateLoad(FCmdlen);
		Value *FCmdlenL32 = Irb.CreateZExt(FCmdlenL, Int32Ty);
		Irb.CreateStore(FCmdlenL32, L);

		// cmd = f->cmd;
		Value *FCmd = Irb.CreateStructGEP(FL, 11);
		Value *Addr = Irb.CreateBitCast(FCmd, IpfwInsnPtrTy);
		Irb.CreateStore(Addr, Cmd);

		// int match;
		Match = Irb.CreateAlloca(Int32Ty, nullptr, "match");

		// int cmdlen;
		// cmdlen = ((cmd)->len & F_LEN_MASK);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *LenPtr = Irb.CreateStructGEP(CmdL, 1);
		Value *Len = Irb.CreateLoad(LenPtr);
		AndOp = Irb.CreateAnd(Len, ConstantInt::get(Int8Ty, F_LEN_MASK));
		Value *AndOp32 = Irb.CreateSExt(AndOp, Int32Ty);
		Irb.CreateStore(AndOp32, Cmdlen);

		// if (skip_or)
		Value *SkipOrL = Irb.CreateLoad(SkipOr);
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
		BasicBlock *matchnz = BasicBlock::Create(Con, "matchnz", Func);
		BasicBlock *matchz = BasicBlock::Create(Con, "matchz", Func);
		BasicBlock *jt = BasicBlock::Create(Con, "jt", Func);
		BasicBlock *sec_cond = BasicBlock::Create(Con, "sec_cond", Func);
		BasicBlock *matchzero = BasicBlock::Create(Con, "matchzero", Func);
		BasicBlock *matchnotzero = BasicBlock::Create(Con, "matchnotzero", Func);
		BasicBlock *is_or = BasicBlock::Create(Con, "is_or", Func);
		BasicBlock *Continue = BasicBlock::Create(Con, "Continue", Func);

		Value *Comp, *AndOp;

		// This are the increments of the for loop.
		// l -= cmdlen, cmd += cmdlen;
		Value *LL = Irb.CreateLoad(L);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *Sub = Irb.CreateNSWSub(LL, CmdlenL);
		Irb.CreateStore(Sub, L);

		// ipfw_insn *cmd; Add to pointer.
		// Note: Since LLVM can't add to a ptr, we can use GEP with casted Ptr.
		// cmd += cmdlen;
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *Add = Irb.CreateInBoundsGEP(CmdL, CmdlenL);
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
		Value *Len = Irb.CreateStructGEP(CmdL, 1);
		Value *LenL = Irb.CreateLoad(Len);
		AndOp = Irb.CreateAnd(LenL, ConstantInt::get(Int8Ty, F_NOT));
		Comp = Irb.CreateICmpNE(AndOp, ConstantInt::get(Int8Ty, 0));
		Irb.CreateCondBr(Comp, jt, sec_cond);

		Irb.SetInsertPoint(jt);
		// match = !match;
		// match = ((match)?0:1);
		Value *MatchL = Irb.CreateLoad(Match);
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
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *AddOp = Irb.CreateAdd(FPosL, ConstantInt::get(Int32Ty, 1));
		Irb.CreateStore(AddOp, FPos);

		// if (done)
		//		break;
		Value *DoneL = Irb.CreateLoad(Done);
		Value *Comp = Irb.CreateICmpNE(DoneL, ConstantInt::get(Int32Ty, 0));
		Irb.CreateCondBr(Comp, End, nextRule());
	}


	void
	emit_end()
	{
		Value *Rule, *TimeUptime, *Str;

		BasicBlock *Jt = BasicBlock::Create(Con, "jt", Func);
		BasicBlock *Jf = BasicBlock::Create(Con, "jf", Func);
		BasicBlock *Ret = BasicBlock::Create(Con, "ret", Func);
		Value *Comp, *AddOp;

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
		Value *DoneL = Irb.CreateLoad(Done);
		Comp = Irb.CreateICmpNE(DoneL, ConstantInt::get(Int32Ty, 0));
		Irb.CreateCondBr(Comp, Jt, Jf);

		Irb.SetInsertPoint(Jt);
		// struct ip_fw *rule = chain->map[f_pos];
		Rule = Irb.CreateAlloca(IpFwPtrTy, nullptr, "rule");
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *ExtFPos = Irb.CreateSExt(FPosL, Int64Ty);
		Value *Map = Irb.CreateStructGEP(Chain, 5);
		Value *MapL = Irb.CreateLoad(Map);
		Value *MapFPos = Irb.CreateInBoundsGEP(MapL, ExtFPos);
		Value *MapFPosL = Irb.CreateLoad(MapFPos);
		Irb.CreateStore(MapFPosL, Rule);

		// uint64_t pcnt;
		// (rule)->pcnt++;
		Value *RuleL = Irb.CreateLoad(Rule);
		Value *Pcnt = Irb.CreateStructGEP(RuleL, 8);
		Value *PcntL = Irb.CreateLoad(Pcnt);
		AddOp = Irb.CreateAdd(PcntL, ConstantInt::get(PcntL->getType(), 1));
		Irb.CreateStore(AddOp, Pcnt);

		// uint64_t bnct;
		// int32_t pktlen
		// (rule)->bcnt += pktlen;
		Value *Bcnt = Irb.CreateStructGEP(RuleL, 9);
		Value *BcntL = Irb.CreateLoad(Bcnt);
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Value *PktlenL64 = Irb.CreateZExt(PktlenL, Int64Ty);
		AddOp = Irb.CreateAdd(BcntL, PktlenL64);
		Irb.CreateStore(AddOp, Bcnt);

		// We have to fit 64 bits into 32
		// (rule)->timestamp = time_uptime;
		// uInt32_t timestamp;
		// int64_t time_uptime;
		Value *TimeUptimeL = Irb.CreateLoad(TimeUptime);
		Value *TimeUptimeL32 = Irb.CreateTrunc(TimeUptimeL, Int32Ty);
		Value *Timestamp = Irb.CreateStructGEP(RuleL, 10);
		Irb.CreateStore(TimeUptimeL32, Timestamp);
		Irb.CreateBr(Ret);

		Irb.SetInsertPoint(Jf);
		//	retval = IP_FW_DENY;
		//	printf("ipfw: ouch!, skip past end of rules, denying packet\n");
		Irb.CreateStore(ConstantInt::get(Int32Ty, IP_FW_DENY), Retval);
		Value *StrFirstElement = Irb.CreateStructGEP(Str, 0);
		Irb.CreateCall(PrintfFunc, StrFirstElement);
		Irb.CreateBr(Ret);

		//Return retval
		Irb.SetInsertPoint(Ret);
		Value *RetvalL = Irb.CreateLoad(Retval);
		Irb.CreateRet(RetvalL);
	}


	// Rules
	void
	emit_nop()
	{
		// rule_nop(int *match)
		Irb.CreateCall(RuleNop, Match);
	}

	void
	emit_forward_mac()
	{
		// rule_forward_mac(cmd->opcode);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *Opcode = Irb.CreateStructGEP(CmdL, 0);
		Value *OpcodeL = Irb.CreateLoad(Opcode);
		// Opcode is u_int8
		Value *OpcodeL32 = Irb.CreateZExt(OpcodeL, Int32Ty);
		Irb.CreateCall(RuleForwardMac, {OpcodeL32});
	}

	void
	emit_jail()
	{
		// rule_jail(&match, offset, proto, cmd, args, ucred_lookup, ucred_cache);
		// We wrote our own version because we don't have ucred_lookup.
		BasicBlock *OffsetNZ = BasicBlock::Create(Con, "R_offsetnotzero", Func);
		BasicBlock *OffsetZE = BasicBlock::Create(Con, "R_offsetiszero", Func);
		BasicBlock *TCPorUDP = BasicBlock::Create(Con, "R_setmatchzero", Func);
		BasicBlock *Continue = BasicBlock::Create(Con, "R_Continue", Func);
		Value *Comp;

		// if (offset != 0)
		//		break;
		// if (proto == IPPROTO_TCP ||
		// 	proto == IPPROTO_UDP)
		//		*match = 0;

		// if (offset != 0)
		//		break;
		Value *OffsetL = Irb.CreateLoad(Offset);
		Comp = Irb.CreateICmpNE(OffsetL, ConstantInt::get(Int16Ty, 0));
		Irb.CreateCondBr(Comp, OffsetNZ, OffsetZE);

		Irb.SetInsertPoint(OffsetNZ);
		// Go to next rule.
		Irb.CreateBr(nextRule());

		// if (proto == IPPROTO_TCP ||
		// 	proto == IPPROTO_UDP)
		//		*match = 0;
		Irb.SetInsertPoint(OffsetZE);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Comp = Irb.CreateICmpEQ(OffsetL, ConstantInt::get(OffsetL->getType(), IPPROTO_TCP));
		Value *Comp2 = Irb.CreateICmpEQ(OffsetL, ConstantInt::get(OffsetL->getType(), IPPROTO_UDP));
		Irb.CreateCondBr(Comp, TCPorUDP, Continue);
		Irb.CreateCondBr(Comp2, TCPorUDP, Continue);

		Irb.SetInsertPoint(TCPorUDP);
		Irb.CreateStore(ConstantInt::get(Int32Ty, 0), Match);
		Irb.CreateBr(Continue);

		// Carry on at the for epilogue.
		Irb.SetInsertPoint(Continue);
	}

	void
	emit_recv()
	{
		// rule_recv(&match, cmd, m, chain, &tablearg);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleRecv, {Match, CmdL, M, Chain, Tablearg});
	}

	void
	emit_xmit()
	{
		// rule_xmit(&match, oif, cmd, chain, &tablearg);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleXmit, {Match, Oif, CmdL, Chain, Tablearg});
	}

	void
	emit_via()
	{
		// rule_via(&match, oif, m, cmd, chain, &tablearg);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleVia, {Match, Oif, M, CmdL, Chain, Tablearg});
	}

	void
	emit_macaddr2()
	{
		// rule_macaddr2(&match, args, cmd);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleMacaddr2, {Match, Args, CmdL});
	}

	void
	emit_mac_type()
	{
		// rule_mac_type(&match, args, cmd, cmdlen, etype);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *EtypeL = Irb.CreateLoad(Etype);
		Irb.CreateCall(RuleMacType, {Match, Args, CmdL, CmdlenL, EtypeL});
	}

	void
	emit_frag()
	{
		// rule_frag(&match, offset);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Irb.CreateCall(RuleFrag, {Match, OffsetL});
	}

	void
	emit_in()
	{
		// rule_in(int *match, struct ifnet *oif)
		Irb.CreateCall(RuleIn, {Match, Oif});
	}

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
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleDiverted, {Match, Args, CmdL});
	}

	void
	emit_proto()
	{
		// rule_proto(&match, proto, cmd);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Irb.CreateCall(RuleProto, {Match, ProtoL, CmdL});
	}

	void
	emit_ip_src()
	{
		// rule_ip_src(&match, is_ipv4, cmd, &src_ip);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIpSrc, {Match, IsIpv4L, CmdL, SrcIp});
	}

	void
	emit_ip_dst_lookup()
	{
		// XXX TODO: Recover the Values for Ucred*.
		// rule_ip_dst_lookup(int *match, ipfw_insn *cmd, int cmdlen, struct
		// ip_fw_args *args, uint32_t *tablearg, int is_ipv4, int is_ipv6,
		// struct ip *ip, struct in_addr *dst_ip, struct in_addr *src_ip,
		// uint16_t dst_port, uint16_t src_port, u_short offset, uint8_t proto,
		// int ucred_lookup, void *ucred_cache, struct ip_fw_chain *chain)
		//
		// Irb.CreateCall(RuleIpDstLookup, {Match, CmdL, CmdlenL, Args, Tablearg,
		// 			   IsIpv4L, IsIpv6L, IpL, DstIp, SrcIp, DstPort, SrcPort,
		// 			   OffsetL, ProtoL, UcredLookup, UcredCache, Chain});
	}

	void
	emit_ip_dst_mask()
	{
		// rule_ip_dst_mask(int *match, int is_ipv4, ipfw_insn *cmd, int cmdlen, struct in_addr *dst_ip, struct in_addr *src_ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *CmdL    = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIpDstMask, {Match, IsIpv4L, CmdL, CmdlenL, DstIp, SrcIp});
	}

	void
	emit_ip_src_me()
	{
		// rule_ip_src_me(int *match, int is_ipv4, int is_ipv6, struct in_addr *src_ip, struct ip_fw_args *args)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIpSrcMe, {Match, IsIpv4L, IsIpv6L, SrcIp, Args});
	}

	void
	emit_ip6_src_me()
	{
#ifdef INET6
		// rule_ip6_src_me(int *match, int is_ipv6, struct ip_fw_args *args)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIp6SrcMe, {Match, IsIpv6L, Args});
#endif /* INET6 */
	}

	void
	emit_ip_src_set()
	{
		// rule_ip_src_set(int *match, int is_ipv4, ipfw_insn *cmd, struct ip_fw_args *args)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIpSrcSet, {Match, IsIpv4L, CmdL, Args});
	}

	void
	emit_ip_dst()
	{
		// rule_ip_dst(int *match, int is_ipv4, ipfw_insn *cmd, struct in_addr *dst_ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIpDst, {Match, IsIpv4L, CmdL, DstIp});
	}

	void
	emit_ip_dst_me()
	{
		// rule_ip_dst_me(int *match, struct ip_fw_args *args, int is_ipv4, int is_ipv6, struct in_addr *dst_ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIpDstMe, {Match, Args, IsIpv4L, IsIpv6L, DstIp});
	}

	void
	emit_ip6_dst_me()
	{
#ifdef INET6
		// rule_ip6_dst_me(int *match, struct ip_fw_args *args, int is_ipv6)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIp6DstMe, {Match, Args, IsIpv6L});
#endif /* INET6 */
	}

	void
	emit_ip_dstport()
	{
		// rule_ip_dstport(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, int cmdlen, uint16_t dst_port, uint16_t src_port)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *DstPortL = Irb.CreateLoad(DstPort);
		Value *SrcPortL = Irb.CreateLoad(SrcPort);
		Irb.CreateCall(RuleIpDstport, {Match, ProtoL, OffsetL, CmdL, CmdlenL, DstPortL, SrcPortL});
	}

	void
	emit_icmptype()
	{
		// rule_icmptype(int *match, u_short offset, uint8_t proto, void *ulp, ipfw_insn *cmd )
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIcmptype, {Match, OffsetL, ProtoL, UlpL, CmdL});
	}

	void
	emit_icmp6type()
	{
#ifdef INET6
		// rule_icmp6type(int *match, u_short offset, int is_ipv6, uint8_t proto, void *ulp, ipfw_insn *cmd)
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIcmp6type, {Match, OffsetL, IsIpv6L, ProtoL, UlpL, Cmd});
#endif /* INET6 */
	}

	void
	emit_ipopt()
	{
		// rule_ipopt(int *match, int is_ipv4, struct ip *ip, ipfw_insn *cmd)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleIpopt, {Match, IsIpv4L, IpPtrL, CmdL});
	}

	void
	emit_ipver()
	{
		// rule_ipver(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleIpver, {Match, IsIpv4L, CmdL, IpPtrL});
	}

	void
	emit_ipttl()
	{
		// rule_ipttl(int *match, int is_ipv4, ipfw_insn *cmd, int cmdlen, struct ip *ip, uint16_t iplen)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *IplenL = Irb.CreateLoad(Iplen);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleIpttl, {Match, IsIpv4L, CmdL, CmdlenL, IpPtrL, IplenL});
	}

	void
	emit_ipprecedence()
	{
		// rule_ipprecedence(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleIpprecedence, {Match, IsIpv4L, CmdL, IpPtrL});
	}

	void
	emit_iptos()
	{
		// rule_iptos(int *match, int is_ipv4, ipfw_insn *cmd, struct ip *ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleIptos, {Match, IsIpv4L, CmdL, IpPtrL});
	}

	void
	emit_dscp()
	{
		// rule_dscp(int *match, int is_ipv4, int is_ipv6, ipfw_insn *cmd, struct ip *ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleDscp, {Match, IsIpv4L, IsIpv6L, CmdL, IpPtrL});
	}

	void
	emit_tcpdatalen()
	{
		// rule_tcpdatalen(int *match, uint8_t proto, u_short offset, void *ulp, uint16_t iplen, int cmdlen, ipfw_insn *cmd, struct ip *ip)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Value *IplenL = Irb.CreateLoad(Iplen);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleTcpdatalen, {Match, ProtoL, OffsetL, UlpL, IplenL, CmdlenL, CmdL, IpPtrL});
	}

	void
	emit_tcpflags()
	{
		// rule_tcpflags(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Irb.CreateCall(RuleTcpflags, {Match, ProtoL, OffsetL, CmdL, UlpL});
	}

	void
	emit_tcpopts()
	{
		// if (rule_tcpopts(int *match, u_int hlen, void *ulp, uint8_t proto, u_short offset, ipfw_insn *cmd, struct mbuf *m, struct ip_fw_args *args))
		// 	goto pullup_failed;
	}

	void
	emit_tcpseq()
	{
		// rule_tcpseq(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Irb.CreateCall(RuleTcpseq, {Match, ProtoL, OffsetL, CmdL, UlpL});
	}

	void
	emit_tcpack()
	{
		// rule_tcpack(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, void *ulp)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Irb.CreateCall(RuleTcpack, {Match, ProtoL, OffsetL, CmdL, UlpL});
	}

	void
	emit_tcpwin()
	{
		// rule_tcpwin(int *match, uint8_t proto, u_short offset, ipfw_insn *cmd, int cmdlen, void *ulp)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Irb.CreateCall(RuleTcpwin, {Match, ProtoL, OffsetL, CmdL, CmdlenL, UlpL});
	}

	void
	emit_estab()
	{
		// rule_estab(int *match, uint8_t proto, u_short offset, void *ulp)
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Irb.CreateCall(RuleEstab, {Match, ProtoL, OffsetL, UlpL});
	}

	void
	emit_altq()
	{
		// rule_altq(int *match, ipfw_insn *cmd, struct mbuf *m, struct ip *ip)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleAltq, {Match, CmdL, M, IpPtrL});
	}

	void
	emit_log()
	{
		// rule_log(int *match, struct ip_fw *f, u_int hlen, struct ip_fw_args *args, struct mbuf *m, struct ifnet *oif, u_short offset, u_short ip6f_mf, uint32_t tablearg, struct ip *ip)
		Value *FL = Irb.CreateLoad(F);
		Value *HlenL = Irb.CreateLoad(Hlen);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Value *Ip6fMfL = Irb.CreateLoad(Ip6fMf);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleLog, {Match, FL, HlenL, Args, M, Oif, OffsetL, Ip6fMfL, TableargL, IpPtrL});
	}

	void
	emit_prob()
	{
		// rule_prob(int *match, ipfw_insn *cmd)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleProb, {Match, CmdL});
	}

	void
	emit_verrevpath()
	{
		// rule_verrevpath(int *match, struct ifnet *oif, struct mbuf *m, int is_ipv6, struct ip_fw_args *args, struct in_addr *src_ip)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Irb.CreateCall(RuleVerrevpath, {Match, Oif, M, IsIpv4L, Args, SrcIp});
	}

	void
	emit_versrcreach()
	{
		//  rule_versrcreach(int *match, u_int hlen, struct ifnet *oif, int is_ipv6, struct ip_fw_args *args, struct in_addr *src_ip)
		Value *HlenL = Irb.CreateLoad(Hlen);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleVersrcreach, {Match, HlenL, Oif, IsIpv6L, Args, SrcIp});
	}

	void
	emit_antispoof()
	{
		//  rule_antispoof(int *match, struct ifnet *oif, u_int hlen, int is_ipv4, int is_ipv6, struct in_addr *src_ip, struct ip_fw_args *args, struct mbuf *m)
		Value *HlenL = Irb.CreateLoad(Hlen);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleAntispoof, {Match, Oif, HlenL, IsIpv4L, IsIpv6L, SrcIp, Args, M});
	}

	void
	emit_ipsec()
	{
#ifdef IPSEC
		// rule_ipsec(int *match, struct mbuf *m)
		Irb.CreateCall(RuleIpsec, {Match, M});
#endif /* IPSEC */
	}

	void
	emit_ip6_src()
	{
#ifdef INET6
		// rule_ip6_src(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIp6Src, {Match, IsIpv6L, Args, CmdL});
#endif /* INET6 */
	}

	void
	emit_ip6_dst()
	{
#ifdef INET6
		// rule_ip6_dst(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleIp6Dst, {Match, IsIpv6L, Args, CmdL});
#endif /* INET6 */
	}

	void
	emit_ip6_dst_mask()
	{
#ifdef INET6
		// rule_ip6_dst_mask(int *match, struct ip_fw_args *args, ipfw_insn *cmd, int cmdlen, int is_ipv6)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleIp6DstMask, {Match, IsIpv6L, Args, CmdL});
#endif /* INET6 */
	}

	void
	emit_flow6id()
	{
#ifdef INET6
		// rule_flow6id(int *match, int is_ipv6, struct ip_fw_args *args, ipfw_insn *cmd)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleFlow6id, {Match, IsIpv6L, Args, CmdL});
#endif /* INET6 */
	}

	void
	emit_ext_hdr()
	{
#ifdef INET6
		// rule_ext_hdr(int *match, int is_ipv6, uint16_t ext_hd, ipfw_insn *cmd)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *ExtHdL = Irb.CreateLoad(ExtHd);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleExtHdr, {Match, IsIpv6L, ExtHdL, CmdL});
#endif /* INET6 */
	}

	void
	emit_ip6()
	{
#ifdef INET6
		// rule_ip6(int *match, int is_ipv6)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Irb.CreateCall(RuleExtHdr, {Match, IsIpv6L});
#endif /* INET6 */
	}

	void
	emit_ip4()
	{
		// rule_ip4(int *match, int is_ipv4)
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Irb.CreateCall(RuleIp4, {Match, IsIpv4L});
	}

	void
	emit_tag()
	{
		// rule_tag(int *match, ipfw_insn *cmd, struct mbuf *m, uint32_t tablearg)
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleTag, {Match, CmdL, M, TableargL});
	}

	void
	emit_fib()
	{
		// rule_fib(int *match, struct ip_fw_args *args, ipfw_insn *cmd)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleFib, {Match, Args, CmdL});
	}

	void
	emit_sockarg()
	{
		// rule_sockarg(int *match, int is_ipv6, uint8_t proto, struct in_addr *dst_ip, struct in_addr *src_ip, uint16_t dst_port, uint16_t src_port, struct ip_fw_args *args, uint32_t *tablearg)
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *DstPortL = Irb.CreateLoad(DstPort);
		Value *SrcPortL = Irb.CreateLoad(SrcPort);
		Irb.CreateCall(RuleSockarg, {Match, IsIpv6L, ProtoL, DstIp, SrcIp, DstPortL, SrcPortL, Args, Tablearg});
	}

	void
	emit_tagged()
	{
		// rule_tagged(int *match, ipfw_insn *cmd, int cmdlen, struct mbuf *m, uint32_t tablearg)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleTagged, {Match, CmdL, CmdlenL, M, TableargL});
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
		// rule_keep_state(int *match, struct ip_fw *f, ipfw_insn *cmd, struct ip_fw_args *args, uint32_t tablearg, int *retval, int *l, int *done)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *FL = Irb.CreateLoad(F);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleKeepState, {Match, FL, CmdL, Args, TableargL, Retval, L, Done});
	}

	void
	emit_check_state()
	{
		// rule_check_state(int *match, int *dyn_dir, ipfw_dyn_rule *q, struct ip_fw_args *args, uint8_t proto, void *ulp, int pktlen, struct ip_fw *f, int *f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, int *cmdlen, int *l)
		Value *QL = Irb.CreateLoad(Q);
		Value *FL = Irb.CreateLoad(F);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleCheckState, {Match, DynDir, QL, Args, ProtoL, UlpL, PktlenL, FL, FPos, Chain, CmdL, Cmdlen, L});
	}

	void
	emit_accept()
	{
		// rule_accept(int *retval, int *l, int *done)
		Irb.CreateCall(RuleAccept, {Retval, L, Done});
	}

	void
	emit_queue()
	{
		// rule_queue(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleQueue, {Args, FPosL, Chain, CmdL, TableargL, Retval, L, Done});
	}

	void
	emit_tee()
	{
		// rule_tee(int *l, int *done, int *retval, ipfw_insn *cmd, struct ip_fw_args *args, int f_pos, uint32_t tablearg, struct ip_fw_chain *chain)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleTee, {L, Done, Retval, CmdL, Args, FPosL, TableargL, Chain});
	}

	void
	emit_count()
	{
		// rule_count(int *l, struct ip_fw *f, int pktlen)
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Value *FL = Irb.CreateLoad(F);
		Irb.CreateCall(RuleCount, {L, FL, PktlenL});
	}

	// TODO - We have to do this directly in LLVM, given that the control flow
	// is modified.
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

	// TODO - We have to do this directly in LLVM, given that the control flow
	// is modified.
	void
	emit_callreturn()
	{
		// rule_callreturn(ipfw_insn *cmd, struct mbuf *m, struct ip_fw *f, struct ip_fw_chain *chain, uint32_t tablearg, int pktlen, int *skip_or, int *cmdlen, int *f_pos, int *l)
		// Value *CmdL = Irb.CreateLoad(Cmd);
		// Value *TableargL = Irb.CreateLoad(Tablearg);
		// Value *PktlenL = Irb.CreateLoad(Pktlen);
		// Value *CmdlenL = Irb.CreateLoad(Cmdlen);
		// Irb.CreateCall(RuleCallreturn, {CmdL, M, F, Chain, TableargL, PktlenL, SkipOr, CmdlenL, FPos, L});
	}

	void
	emit_reject()
	{
		// rule_reject(u_int hlen, int is_ipv4, u_short offset, uint8_t proto, void *ulp, struct mbuf *m, struct in_addr *dst_ip, struct ip_fw_args *args, ipfw_insn *cmd, uint16_t iplen, struct ip *ip)
		Value *HlenL = Irb.CreateLoad(Hlen);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *UlpL = Irb.CreateLoad(Ulp);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IplenL = Irb.CreateLoad(Iplen);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleReject, {HlenL, IsIpv4L, OffsetL, ProtoL, UlpL, M, DstIp, Args, CmdL, IplenL, IpPtrL});
	}

	void
	emit_unreach6()
	{
#ifdef INET6
		// rule_unreach6(u_int hlen, int is_ipv6, u_short offset, uint8_t proto, uint8_t icmp6_type, struct mbuf *m, struct ip_fw_args *args, ipfw_insn *cmd, struct ip *ip)
		Value *HlenL = Irb.CreateLoad(Hlen);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *OffsetL = Irb.CreateLoad(Offset);
		Value *ProtoL = Irb.CreateLoad(Proto);
		Value *Icmp6TypeL = Irb.CreateLoad(Icmp6TypeL);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleUnreach6, {HlenL, IsIpv6L, OffsetL, ProtoL, Icmp6TypeL, M, Args, CmdL, Ip});
#endif /* INET6 */
	}

	void
	emit_deny()
	{
		// rule_deny(int *l, int *done, int *retval)
		Irb.CreateCall(RuleDeny, {L, Done, Retval});
	}

	void
	emit_forward_ip()
	{
		// rule_forward_ip(struct ip_fw_args *args, ipfw_dyn_rule *q, struct ip_fw *f, int dyn_dir, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
		Value *QL = Irb.CreateLoad(Q);
		Value *FL = Irb.CreateLoad(F);
		Value *DynDirL = Irb.CreateLoad(DynDir);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleForwardIp, {Args, QL, FL, DynDirL, CmdL, TableargL, Retval, L, Done});
	}

	void
	emit_forward_ip6()
	{
#ifdef INET6
		// rule_forward_ip6(struct ip_fw_args *args, ipfw_dyn_rule *q, struct ip_fw *f, int dyn_dir, ipfw_insn *cmd, int *retval, int *l, int *done)
		Value *DynDirL = Irb.CreateLoad(DynDir);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *RetvalL = Irb.CreateLoad(Retval);
		Irb.CreateCall(RuleForwardIp6, {Args, Q, F, DynDirL, CmdL, Retval, L, Done});
#endif /* INET6 */
	}

	void
	emit_ngtee()
	{
		// rule_ngtee(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, uint32_t tablearg, int *retval, int *l, int *done)
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleNgtee, {Args, FPosL, Chain, CmdL, TableargL, Retval, L, Done});
	}

	void
	emit_setfib()
	{
		// rule_setfib(struct ip_fw *f, int pktlen, uint32_t tablearg, ipfw_insn *cmd, struct mbuf *m, struct ip_fw_args *args, int *l)
		Value *FL = Irb.CreateLoad(F);
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Irb.CreateCall(RuleSetfib, {FL, PktlenL, TableargL, CmdL, M, Args, L});
	}

	void
	emit_setdscp()
	{
		// rule_setdscp(ipfw_insn *cmd, struct ip *ip, int is_ipv4, int is_ipv6, uint32_t tablearg, struct ip_fw *f, int pktlen, int *l)
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Value *IsIpv4L = Irb.CreateLoad(IsIpv4);
		Value *IsIpv6L = Irb.CreateLoad(IsIpv6);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Value *FL = Irb.CreateLoad(F);
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Irb.CreateCall(RuleSetdscp, {CmdL, IpPtrL, IsIpv4L, IsIpv6L, TableargL, FL, PktlenL, L});
	}

	void
	emit_nat()
	{
		// rule_nat(struct ip_fw_args *args, int f_pos, struct ip_fw_chain *chain, ipfw_insn *cmd, struct mbuf *m, uint32_t tablearg, int *retval, int *done, int *l)
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *CmdL = Irb.CreateLoad(Cmd);
		Value *TableargL = Irb.CreateLoad(Tablearg);
		Irb.CreateCall(RuleNat, {Args, FPosL, Chain, CmdL, M, TableargL, Retval, Done, L});
	}

	void
	emit_reass()
	{
		// rule_reass(struct ip_fw *f, int f_pos, struct ip_fw_chain *chain, int pktlen, struct ip *ip, struct ip_fw_args *args, struct mbuf *m, int *retval, int *done, int *l)
		Value *FL = Irb.CreateLoad(F);
		Value *FPosL = Irb.CreateLoad(FPos);
		Value *PktlenL = Irb.CreateLoad(Pktlen);
		Value *IpPtrL = Irb.CreateLoad(IpPtr);
		Irb.CreateCall(RuleReass, {FL, FPosL, Chain, PktlenL, IpPtrL, Args, M, Retval, Done, L});
	}
};

// Function to test compilation code.
// Filtering code has to be tested by real usage.
// Todo: We have to work on a system with variables like INET6 set.
void
test_compilation()
{
	ipfwJIT compiler(1);
	compiler.emit_outer_for_prologue();
	compiler.emit_inner_for_prologue();
	// Rule to test
	printf("Testing rule compilation\n");
	compiler.emit_nop();
	compiler.emit_forward_mac();
	compiler.emit_jail();
	compiler.emit_recv();
	compiler.emit_xmit();
	compiler.emit_via();
	compiler.emit_macaddr2();
	compiler.emit_mac_type();
	compiler.emit_frag();
	compiler.emit_in();
	compiler.emit_layer2();
	compiler.emit_diverted();
	compiler.emit_proto();
	compiler.emit_ip_src();
	// compiler.emit_ip_dst_lookup();
	compiler.emit_ip_dst_mask();
	compiler.emit_ip_src_me();
	compiler.emit_ip6_src_me();
	compiler.emit_ip_src_set();
	compiler.emit_ip_dst();
	compiler.emit_ip_dst_me();
	compiler.emit_ip6_dst_me();
	compiler.emit_ip_dstport();
	compiler.emit_icmptype();
	compiler.emit_icmp6type();
	compiler.emit_ipopt();
	compiler.emit_ipver();
	compiler.emit_ipttl();
	compiler.emit_ipprecedence();
	compiler.emit_iptos();
	compiler.emit_dscp();
	compiler.emit_tcpdatalen();
	compiler.emit_tcpflags();
	// compiler.emit_tcpopts();
	compiler.emit_tcpseq();
	compiler.emit_tcpack();
	compiler.emit_tcpwin();
	compiler.emit_estab();
	compiler.emit_altq();
	compiler.emit_log();
	compiler.emit_prob();
	compiler.emit_verrevpath();
	compiler.emit_versrcreach();
	compiler.emit_antispoof();
	compiler.emit_ipsec();
	compiler.emit_ip6_src();
	compiler.emit_ip6_dst();
	compiler.emit_ip6_dst_mask();
	compiler.emit_flow6id();
	compiler.emit_ext_hdr();
	compiler.emit_ip6();
	compiler.emit_ip4();
	compiler.emit_tag();
	compiler.emit_fib();
	compiler.emit_sockarg();
	compiler.emit_tagged();
	compiler.emit_keep_state();
	compiler.emit_check_state();
	compiler.emit_accept();
	compiler.emit_queue();
	compiler.emit_tee();
	compiler.emit_count();
	//// Functions that we shouldn't call yet.
	//// compiler.emit_skipto();
	//// compiler.emit_callreturn();
	compiler.emit_reject();
	compiler.emit_unreach6();
	compiler.emit_deny();
	compiler.emit_forward_ip();
	compiler.emit_forward_ip6();
	compiler.emit_ngtee();
	compiler.emit_setfib();
	compiler.emit_setdscp();
	compiler.emit_nat();
	compiler.emit_reass();
	// Finish writing the code.
	compiler.emit_inner_for_epilogue();
	compiler.emit_outer_for_epilogue();
	compiler.end_rule();
	compiler.emit_end();
	compiler.compile();
	err(1, "Compilation");
}

extern "C" funcptr
compile_code(struct ip_fw_args *args, struct ip_fw_chain *chain)
{
	int res;
	int f_pos = 0;

	if (chain->n_rules == 0)
		return (NULL);

	test_compilation();

	ipfwJIT compiler(chain->n_rules);

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
		compiler.emit_outer_for_prologue();

		// For each different command.
		for (l = f->cmd_len, cmd = f->cmd ; l > 0 ;
		    l -= cmdlen, cmd += cmdlen) {
/* check_body: */
			cmdlen = F_LEN(cmd);
			compiler.emit_inner_for_prologue();
			switch (cmd->opcode) {
			printf("compiling opcode: %d\n", cmd->opcode);
			case O_NOP:
				compiler.emit_nop();
				break;

			// XXX Not implemented in netmap-ipfw
			case O_FORWARD_MAC:
				compiler.emit_forward_mac();
				break;

			case O_GID:
			case O_UID:
			case O_JAIL:
				compiler.emit_jail();
				break;

			case O_RECV:
				compiler.emit_recv();
				break;

			case O_XMIT:
				compiler.emit_xmit();
				break;

			case O_VIA:
				compiler.emit_via();
				break;

			case O_MACADDR2:
				compiler.emit_macaddr2();
				break;

			case O_MAC_TYPE:
				compiler.emit_mac_type();
				break;

			case O_FRAG:
				compiler.emit_frag();
				break;

			case O_IN:
				compiler.emit_in();
				break;

			case O_LAYER2:
				compiler.emit_layer2();
				break;

			case O_DIVERTED:
				compiler.emit_diverted();
				break;

			case O_PROTO:
				compiler.emit_proto();
				break;

			case O_IP_SRC:
				compiler.emit_ip_src();
				break;

			case O_IP_SRC_LOOKUP:
			case O_IP_DST_LOOKUP:
				compiler.emit_ip_dst_lookup();
				break;

			case O_IP_SRC_MASK:
			case O_IP_DST_MASK:
				compiler.emit_ip_dst_mask();
				break;

			case O_IP_SRC_ME:
				compiler.emit_ip_src_me();
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_SRC_ME:
				compiler.emit_ip6_src_me();
#endif /* INET6 */
				break;

			case O_IP_DST_SET:
			case O_IP_SRC_SET:
				compiler.emit_ip_src_set();
				break;

			case O_IP_DST:
				compiler.emit_ip_dst();
				break;

			case O_IP_DST_ME:
				compiler.emit_ip_dst_me();
				
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_DST_ME:
				compiler.emit_ip6_dst_me();
#endif /* INET6 */
				break;


			case O_IP_SRCPORT:
			case O_IP_DSTPORT:
				compiler.emit_ip_dstport();
				break;

			case O_ICMPTYPE:
				compiler.emit_icmptype();
				break;

#ifdef INET6
			case O_ICMP6TYPE:
				compiler.emit_icmp6type();
				break;
#endif /* INET6 */
			case O_IPOPT:
				compiler.emit_ipopt();
				break;

			case O_IPVER:
				compiler.emit_ipver();
				break;

			case O_IPID:
			case O_IPLEN:
			case O_IPTTL:
				compiler.emit_ipttl();
				break;

			case O_IPPRECEDENCE:
				compiler.emit_ipprecedence();
				break;

			case O_IPTOS:
				compiler.emit_iptos();
				break;

			case O_DSCP:
				compiler.emit_dscp();
				break;

			case O_TCPDATALEN:
				compiler.emit_tcpdatalen();
				break;

			case O_TCPFLAGS:
				compiler.emit_tcpflags();
				break;

			case O_TCPOPTS:
				compiler.emit_tcpopts();
				break;

			case O_TCPSEQ:
				compiler.emit_tcpseq();
				break;

			case O_TCPACK:
				compiler.emit_tcpack();
				break;

			case O_TCPWIN:
				compiler.emit_tcpwin();
				break;

			case O_ESTAB:
				compiler.emit_estab();
				break;

			case O_ALTQ:
				compiler.emit_altq();
				break;

			case O_LOG:
				compiler.emit_log();
				break;

			case O_PROB:
				compiler.emit_prob();
				break;

			case O_VERREVPATH:
				compiler.emit_verrevpath();
				break;

			case O_VERSRCREACH:
				compiler.emit_versrcreach();
				break;

			case O_ANTISPOOF:
				compiler.emit_antispoof();
				break;

			case O_IPSEC:
#ifdef IPSEC
				compiler.emit_ipsec();
#endif
				/* otherwise no match */
				break;

#ifdef INET6
			case O_IP6_SRC:
				compiler.emit_ip6_src();
				break;

			case O_IP6_DST:
				compiler.emit_ip6_dst();
				break;

			case O_IP6_SRC_MASK:
			case O_IP6_DST_MASK:
				compiler.emit_ip6_dst_mask();
				break;

			case O_FLOW6ID:
				compiler.emit_flow6id();
				break;

			case O_EXT_HDR:
				compiler.emit_ext_hdr();
				break;

			case O_IP6:
				compiler.emit_ip6();
				break;
#endif /* INET6 */

			case O_IP4:
				compiler.emit_ip4();
				break;

			case O_TAG: 
				compiler.emit_tag();
				break;

			case O_FIB: /* try match the specified fib */
				compiler.emit_fib();
				break;

			case O_SOCKARG:
				compiler.emit_sockarg();
				break;

			case O_TAGGED:
				compiler.emit_tagged();
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
				compiler.emit_keep_state();
				break;

			case O_PROBE_STATE:
			case O_CHECK_STATE:
				compiler.emit_check_state();
				break;

			case O_ACCEPT:
				compiler.emit_accept();
				break;

			case O_PIPE:
			case O_QUEUE:
				compiler.emit_queue();
				break;

			case O_DIVERT:
			case O_TEE:
				compiler.emit_tee();
				break;

			case O_COUNT:
				compiler.emit_count();
				break;

			case O_SKIPTO:
				compiler.emit_skipto();
			    continue;
			    break;	/* NOTREACHED */

			case O_CALLRETURN:
				compiler.emit_callreturn();
				continue;
				break;	/* NOTREACHED */

			case O_REJECT:
				compiler.emit_reject();
				/* FALLTHROUGH */
#ifdef INET6
			case O_UNREACH6:
				compiler.emit_unreach6();
				/* FALLTHROUGH */
#endif /* INET6 */
			case O_DENY:
				compiler.emit_deny();
				break;

			case O_FORWARD_IP:
				compiler.emit_forward_ip();
				break;

#ifdef INET6
			case O_FORWARD_IP6:
				compiler.emit_forward_ip6();
				break;
#endif /* INET6 */

			case O_NETGRAPH:
			case O_NGTEE:
				compiler.emit_ngtee();
				break;

			case O_SETFIB:
				compiler.emit_setfib();
				break;

			case O_SETDSCP:
				compiler.emit_setdscp();
				break;

			case O_NAT:
				compiler.emit_nat();
				break;

			case O_REASS:
				compiler.emit_reass();
				break;

			default:
				panic("-- unknown opcode %d\n", cmd->opcode);
			} /* end of switch() on opcodes */
			compiler.emit_inner_for_epilogue();
		}	/* end of inner loop, scan opcodes */
		// Rule ends.
		compiler.emit_outer_for_epilogue();
		compiler.end_rule();
	}		/* end of outer for, scan rules */

	compiler.emit_end();

	// Once we're done iterating through the rules, return the pointer.
	return (compiler.compile());
}
