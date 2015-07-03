Note: This README is taken from the original netmap-ipfw, and adopted as needed
here.

netmap-ipfwjit
==============
This directory contains a version of ipfw and dummynet that can
run in userland, using NETMAP as the backend for packet I/O.
This permits a throughput about 10 times higher than the
corresponding in-kernel version. Luigi has measured about 6.5 Mpps
for plain filtering, and 2.2 Mpps going through a pipe.
Some optimizations are possible when running on netmap pipes,
or other netmap ports that support zero copy.

To build the code simply run
	make NETMAP_INC=/some/where/with/netmap-release/sys

pointing to the netmap 'sys' directory
(the makefile uses gmake underneath)

The base version comes from FreeBSD-HEAD -r '{2012-08-03}'
(and subsequently updated in late 2013)
with small modifications listed below

	netinet/ipfw
	    ip_dn_io.c
		support for on-stack mbufs
	    ip_fw2.c
		some conditional compilation for functions not
		available in userspace
	    ip_fw_log.c
		revise snprintf, SNPARGS (MAC)


sbin/ipfw and the kernel counterpart communicate through a
TCP socket (localhost:5555) carrying the raw data that would
normally be carried on seg/getsockopt.

Testing
=======
For testing purposes, opening a telnet session to port 5556 and
typing some bytes will start a fake 'infinite source' so you can
check how fast your ruleset works.

	gmake
	dummynet/ipfw & # preferably in another window
	telnet localhost 5556 # type some bytes to start 'traffic'

	sh -c "while true; do ipfw/ipfw show; ipfw/ipfw zero; sleep 1; done"

(on an i7-3400 Luigi gets about 15 Mpps)

Real packet I/O is possible using netmap info.iet.unipi.it/~luigi/netmap/ You
can use a couple of VALE switches (part of netmap, included in ./tools/) to
connect a source and sink to the userspace firewall, as follows:

   [pkt-gen]-->--[valeA:s]-->--[kipfw]-->--[valeA:r]-->--[pkt-gen]

The commands to run (in separate windows) are
	# preliminarly, load the netmap module if needed
	sudo kldload netmap.ko

	# connect the firewall to two vale switches
	./kipfw valeA:s valeA:r &

	# configure ipfw/dummynet
	ipfw/ipfw show	# or other

	# start the sink/receptor
	pkt-gen -i valeA:r -f rx

	# start an infinite source
	pkt-gen -i valeA:s -f tx

	# plain again with the firewall and enjoy
	ipfw/ipfw show  # or other

Luigi reports that on his i7-3400 he got about 6.5 Mpps with a single
rule, and about 2.2 Mpps when going through a dummynet pipe. This is for a
single process handling the traffic.

Simple benchmarch
=================
We executed and tested it with just one rule (accept all), and 1k packets and
this is what we found (This was done on a computer with a 3 year-old i7):
- Compilation time: 130ms (Amortized when 41440 packets are filtered).
- Filtering time (JIT): 523us
- Filtering time (Interpreter): 3664us

This basically means we'll have a x7 speedup compared to the interpreter, and
the more rules we have, the better the speedup will be.

Tests and rulesets
==================
At some point, we'll test the firewall properly with a set of rulesets, that
will be added to ./rulesets and commented adequately.

Current state
=============
- The JIT compiler is not working.
- All the commands except the flow-modifying ones should work well.

