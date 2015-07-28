#
# this is a gnu makefile

# Use LLVM 3.5.
# CXXFLAGS includes -g
LLVM_CONFIG=/home/dpl/wrk/llvm_build/bin/llvm-config
CC=clang35
CCXX=clang++35
LLVM_VERSION=-DLLVM_MAJOR=3 -DLLVM_MINOR=5
LLVM_CXXFLAGS=`${LLVM_CONFIG} --cxxflags`
LLVM_LDFLAGS=`${LLVM_CONFIG} --ldflags`
LLVM_SYSLIBS=`${LLVM_CONFIG} --system-libs`
LLVM_LIBS=`${LLVM_CONFIG} --libs all`


BSD_HEAD ?= /home/luigi/FreeBSD/head
NETMAP_INC ?= ../netmap-release/sys

OBJDIR=objs
OSARCH := $(shell uname)
OSARCH := $(findstring $(OSARCH),FreeBSD Linux Darwin)
ifeq ($(OSARCH),)
    OSARCH := Windows
endif

ifeq ($V,) # no echo
    MSG=@echo
    HIDE=@
else
    MSG=@\#
    HIDE=
endif

# ipfw and kipfw are built in subdirs so the paths for
# headers refer to one directory up
INCDIRS += -I ../$(OBJDIR)/include_e -DEMULATE_SYSCTL
INCDIRS += -I ../sys -I ../extra/sys -I ../extra/sys/contrib/pf
.c.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CC) $(CFLAGS) -O0 -g -c $< -o $@
