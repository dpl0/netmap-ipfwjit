# ipfw rules script to clear all rules and install an any to any
repo="$HOME/wrk/netmap-ipfwjit"
ipfw="$repo/ipfw/ipfw"
kipfw="$repo/kipfw"

control="re0"          # control interface
loop="lo0"
in="valeA:s"
out="valeA:r"
cmd="$ipfw -q add "     # build rule prefix

# Actual commands
# We need to have $kipfw running.
$ipfw -q -f flush       # Delete all rules
# Allow messages to and from the crontol interface
$cmd 00005 allow all from any to any via $control

# No restrictions on Loopback Interface
$cmd 00010 allow all from any to any via $loop

# Pass only UDP packets between cxl0 and cxl1

$cmd 00500 allow udp from any to any in via $in

# Everything else is denied and logged
$cmd 00999 deny log all from any to any
