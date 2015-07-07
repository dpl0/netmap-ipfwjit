# ipfw rules script to clear all rules and install an any to any
repo="$HOME/wrk/netmap-ipfwjit"
ipfw="$repo/ipfw/ipfw"
kipfw="$repo/kipfw"

cmd="$ipfw -q add "	# build rule prefix

# Actual commands
# We need to have $kipfw running.
$ipfw -q -f flush	# Delete all rules.
$cmd 0500 allow ip from any to any
