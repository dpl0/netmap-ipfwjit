Tests
=====
This directory contains all the scripts used to test the JIT compiled firewall,
both for the netmap version, and the base version (when done). These tests use
conductor to perform the execution of the different commands, and all of them
are for three hosts:

- Source: The host where the packets are generated, mostly with pkt-gen, found
  in ../tools.
- DUT (Device Under Test): This is the host that performs the packet filtering.
  performed.
- Sink: Host where all the packets end after being filtered by ipfwjit.

Hierarchy
=========
- Configs: Contain all the different configuration files that will be loaded to
  the firewall.
- Resutls: Where the results of each test will be saved.
- Tests: There is a directory here for each different test, and each folder
  will contain the different config files for conductor.
